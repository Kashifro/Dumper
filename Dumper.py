"""
Dumper5000
RTTI-based vtable extractor for IDA Pro. struct creation goes through idc
directly (get_struc_id/add_struc/add_struc_member); only the optional
tinfo-on-member annotation falls back between ida_struct/idaapi, since that
one's missing entirely on some IDA builds.
"""

import idaapi, idautils, idc, ida_name, ida_bytes, ida_segment, ida_ida
import os, re

# tinfo-on-member setters live on ida_struct in some IDA builds, on idaapi in
# others, and on neither in this idc-only build — tinfo is a nice-to-have, so
# missing means "skip it", not "crash".
try:
    from ida_struct import get_struc, get_member, set_member_tinfo
except ImportError:
    get_struc       = getattr(idaapi, "get_struc", None)
    get_member      = getattr(idaapi, "get_member", None)
    set_member_tinfo = getattr(idaapi, "set_member_tinfo", None)

VTBL_SUFFIX  = "__vtbl"
VTBL_MEMNAME = "__vftable"

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False

#### pointer width ###

def _is_64bit():
    try:    return ida_ida.inf_is_64bit()
    except: return idaapi.get_inf_structure().is_64bit()

PTR_SIZE = 8 if _is_64bit() else 4
BADADDR  = idaapi.BADADDR
_FF_PTR  = idc.FF_QWORD if PTR_SIZE == 8 else idc.FF_DWORD

# this build doesn't expose the STRUC_ERROR_MEMBER_* names — values are
# stable across IDA versions (0 = ok, -3 = name collision), so fall back to them.
_STRUC_ERROR_OK   = getattr(idc, "STRUC_ERROR_MEMBER_OK", 0)
_STRUC_ERROR_NAME = getattr(idc, "STRUC_ERROR_MEMBER_NAME", -3)

def read_ptr(ea):
    return ida_bytes.get_qword(ea) if PTR_SIZE == 8 else ida_bytes.get_dword(ea)

def _is_arm():
    try:
        return idaapi.ph.id == idaapi.PLFM_ARM
    except Exception:
        return False

# arm64-v8a (Android) sometimes tags pointer top bits (PAC / memory tagging);
# x86_64 doesn't, so only mask there.
IS_ARM64 = _is_arm() and PTR_SIZE == 8

def _mask_ptr(val):
    return (val & 0x00FFFFFFFFFFFFFF) if (IS_ARM64 and val) else val

#### helpers ###

def _seg_ok(ea):
    return ea and ea != BADADDR and ida_segment.getseg(ea) is not None

def _exec_seg(ea):
    s = ida_segment.getseg(ea)
    if not s:
        return False
    # extern/import stubs (e.g. __cxa_pure_virtual) commonly land in an XTRN
    # segment with no exec perm — that's a real vtable slot, not end-of-array.
    return bool(s.perm & ida_segment.SEGPERM_EXEC) or s.type == idaapi.SEG_XTRN

def _name(ea):
    return ida_name.get_name(ea) or ""

def _demangled(ea):
    raw = _name(ea)
    return idc.demangle_name(raw, idc.get_inf_attr(idc.INF_SHORT_DN)) or raw

def _safe_id(s):
    return re.sub(r"[^A-Za-z0-9_]", "_", s)

def _strip_len(mangled):
    """'17HoverTextRenderer' → 'HoverTextRenderer'"""
    m = re.match(r"^\d+([A-Za-z_].*)$", mangled)
    return m.group(1) if m else mangled

#### find _ZTI ###

def find_typeinfo(classname):
    bare = _strip_len(classname)
    for name in dict.fromkeys([bare, classname]):
        if name.startswith("N") and name.endswith("E"):
            sym = "_ZTI{}".format(name)                       # already a mangled nested-name, e.g. N3mce12TextureGroupE
        elif "::" in name:
            parts = name.split("::")
            sym = "_ZTIN{}E".format("".join("{}{}".format(len(p), p) for p in parts))  # mce::TextureGroup → N3mce12TextureGroupE
        else:
            sym = "_ZTI{}{}".format(len(name), name)          # flat identifier, e.g. 4Item
        ea = ida_name.get_name_ea(BADADDR, sym)
        if ea != BADADDR:
            return ea
    for ea, sym in idautils.Names():
        if "ZTI" in sym and bare in sym:
            return ea
    return BADADDR

def find_vtable_direct(classname):
    """Fallback when there's no _ZTI (e.g. partial -fno-rtti, or the class is never
    dynamic_cast/typeid'd so the compiler dropped RTTI but kept the vtable). No ancestor
    chain exists without RTTI, so slots from this path never climb — owner is always self."""
    bare = _strip_len(classname)
    for name in dict.fromkeys([bare, classname]):
        if name.startswith("N") and name.endswith("E"):
            sym = "_ZTV{}".format(name)
        elif "::" in name:
            parts = name.split("::")
            sym = "_ZTVN{}E".format("".join("{}{}".format(len(p), p) for p in parts))
        else:
            sym = "_ZTV{}{}".format(len(name), name)
        ea = ida_name.get_name_ea(BADADDR, sym)
        if ea != BADADDR:
            return ea + PTR_SIZE  # symbol sits at the offset-to-top header, not the first slot
    return BADADDR

#### vtable discovery & slot reading ###

def _is_sentinel(ea):
    val = read_ptr(ea)
    if val != 0 and not (val > 0xFFFFFFFF00000000):
        return False
    nxt = _mask_ptr(read_ptr(ea + PTR_SIZE))
    if not _seg_ok(nxt):
        return False
    nm = _name(nxt)
    return "_ZTI" in nm or "typeinfo for" in nm

def _raw_slots(vtable_ea):
    slots = []
    seg   = ida_segment.getseg(vtable_ea)
    if not seg:
        return slots
    ea = vtable_ea
    while ea < seg.end_ea:
        if _is_sentinel(ea):
            break
        func_ea = _mask_ptr(read_ptr(ea))
        if func_ea != 0 and not _exec_seg(func_ea):
            break
        slots.append(func_ea)
        ea += PTR_SIZE
    return slots

def vtable_chunks(ti_ea):
    """All _ZTV chunks (primary + secondary, for multiple-inheritance vtables) for a given _ZTI."""
    chunks = []
    for xref in idautils.XrefsTo(ti_ea, 0):
        ti_cell = xref.frm
        raw_ott = read_ptr(ti_cell - PTR_SIZE)
        vtbl_ea = ti_cell + PTR_SIZE

        if raw_ott == 0:
            ott = 0
        elif raw_ott > 0xFFFFFFFF00000000:
            ott = raw_ott - (1 << 64)
        else:
            continue

        if not _raw_slots(vtbl_ea):
            continue
        chunks.append((ott, vtbl_ea))

    chunks.sort(key=lambda t: (t[0] != 0, t[0]))
    return chunks

#### slot ownership via RTTI ancestor walk ###
# We don't trust the typeinfo's own vtable-pointer name to decide si vs vmi —
# in this it can point at the vmi vtable while word[2] still holds a
# plain single direct parent pointer (si-shaped data, vmi-named vtable; maybe
# ICF/weak-symbol folding). Instead validate the data itself: try the simple
# single-pointer read first, and only fall back to the real vmi
# [flags][base_count][base_ti_ptr,...]×N parse if that doesn't look sane.

def _looks_like_ti_ptr(ea):
    """True if `ea` is a pointer to a real type_info object (named _ZTI...)."""
    return _seg_ok(ea) and _name(ea).startswith("_ZTI")

def _parent_ti(ti_ea):
    """Base type_info ptr to walk for primary-vtable ownership, or None at the root."""
    direct = _mask_ptr(read_ptr(ti_ea + 2 * PTR_SIZE))
    if _looks_like_ti_ptr(direct):
        return direct
    base_count = ida_bytes.get_dword(ti_ea + 2 * PTR_SIZE + 4)
    base_ti = _mask_ptr(read_ptr(ti_ea + 2 * PTR_SIZE + 8)) if base_count >= 1 else None
    return base_ti if (base_ti and _looks_like_ti_ptr(base_ti)) else None

def _classname_from_ti(ti_ea):
    dem = _demangled(ti_ea)
    if dem.startswith("typeinfo for "):
        return dem[len("typeinfo for "):]
    nm = _name(ti_ea)
    return _strip_len(nm[4:]) if nm.startswith("_ZTI") else nm

def _ancestor_owner_table(ti_ea, ott=0):
    """[(classname, slots_for_this_offset_domain), ...] for self + every ancestor, computed
    ONCE per domain (not once per slot — vtable_chunks does an xref scan, too slow to repeat
    19x). `ott` selects which chunk: 0 for the primary vtable, nonzero for a secondary
    (multiple-inheritance) domain. An ancestor with no chunk at that exact offset breaks the
    climb there — correct when the offset is consistent up the chain, which covers the
    common single-level-MI case but isn't guaranteed once a base's placement shifts deeper
    in a multi-level diamond hierarchy."""
    table, seen, cur = [], set(), ti_ea
    while cur and cur not in seen:
        seen.add(cur)
        chunks = vtable_chunks(cur)
        match  = next((c for c in chunks if c[0] == ott), None)
        slots  = _raw_slots(match[1]) if match else []
        table.append((_classname_from_ti(cur), slots))
        cur = _parent_ti(cur)
    return table

def slot_owner(owner_table, classname, slot_idx, func_ea):
    """Walk the precomputed ancestor table while func_ea still matches at this index —
    the most-base match is who actually declared/owns the slot."""
    owner = classname
    for cn, slots in owner_table[1:]:
        if slot_idx >= len(slots) or slots[slot_idx] != func_ea:
            break
        owner = cn
    return owner

#### decompile a single slot (Hex-Rays) ###

def _decompile(func_ea):
    if not HAS_HEXRAYS or not func_ea:
        return None
    try:
        hf = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(func_ea, hf)
        if cfunc:
            return str(cfunc)
        return "// decompile failed: {}".format(hf.desc() if hf else "unknown")
    except Exception as ex:
        return "// decompile failed: {}".format(ex)

#### struct field recovery via AST (Hex-Rays) ###

if HAS_HEXRAYS:
    class StructRecoveryVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, cfunc, this_idx):
            ida_hexrays.ctree_visitor_t.__init__(
                self, ida_hexrays.CV_FAST | ida_hexrays.CV_PARENTS)
            self.this_idx = this_idx
            self.fields   = {}

        def visit_expr(self, expr):
            if expr.op != ida_hexrays.cot_add:
                return 0

            def _strip_cast(e):
                while e and e.op == ida_hexrays.cot_cast:
                    e = e.x
                return e

            x = _strip_cast(expr.x)
            y = _strip_cast(expr.y)

            this_op = num_op = None
            if x and x.op == ida_hexrays.cot_var and x.v.idx == self.this_idx:
                this_op, num_op = x, expr.y
            elif y and y.op == ida_hexrays.cot_var and y.v.idx == self.this_idx:
                this_op, num_op = y, expr.x

            num_op = _strip_cast(num_op)
            if not (this_op and num_op and num_op.op == ida_hexrays.cot_num):
                return 0

            offset = num_op.numval()
            parent = self.parent_expr()
            size, tname = 0, "?"  # "?" = no parent context at all, distinct from a real void*

            if parent:
                if parent.op == ida_hexrays.cot_ptr:
                    size  = parent.type.get_ptrarr_objsize()
                    pt    = parent.type.get_pointed_object()
                    tname = str(pt) if pt else "void*"
                elif parent.op in (ida_hexrays.cot_asg, ida_hexrays.cot_cast):
                    size  = parent.type.get_size()
                    tname = str(parent.type)

            if size <= 0:
                size = PTR_SIZE

            if offset not in self.fields or self.fields[offset]['size'] < size:
                self.fields[offset] = {'size': size, 'type': tname}
            return 0


def _scan_struct_fields(func_ea, struct_fields):
    if not HAS_HEXRAYS or not func_ea:
        return
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return

        this_idx = -1
        lvars    = cfunc.get_lvars()
        for i in range(lvars.size()):
            lv = lvars.at(i)
            if lv.is_arg_var and ("this" in lv.name or i == 0):
                this_idx = i
                break
        if this_idx == -1:
            return

        visitor = StructRecoveryVisitor(cfunc, this_idx)
        visitor.apply_to(cfunc.body, None)

        for off, info in visitor.fields.items():
            if off not in struct_fields or struct_fields[off]['size'] < info['size']:
                struct_fields[off] = info
    except Exception:
        pass

#### IDA struct creation (idc-only, IDA 9.x) ###

def _get_or_create_struc(name):
    safe_name = name if name[:1].isalpha() or name[:1] == "_" else "_" + name
    sid = idc.get_struc_id(safe_name)
    if sid in (BADADDR, None, idc.BADADDR):
        sid = idc.add_struc(idc.BADADDR, safe_name, 0)
    return sid

def _add_or_skip_member(sid, name, offset, tinfo):
    """Add a pointer-sized member at `offset`. Returns True if it exists after the call."""
    if sid in (None, BADADDR, idc.BADADDR):
        return False
    if idc.get_member_name(sid, offset):
        return True

    flag = _FF_PTR | idc.FF_0OFF
    serr = idc.add_struc_member(sid, name, offset, flag, -1, PTR_SIZE)

    if serr == _STRUC_ERROR_NAME:
        alt = "{}_at_{:x}".format(name, offset)
        serr = idc.add_struc_member(sid, alt, offset, flag, -1, PTR_SIZE)

    if serr != _STRUC_ERROR_OK:
        return False

    if tinfo is not None and get_struc and get_member and set_member_tinfo:
        try:
            struc = get_struc(sid)
            mem   = get_member(struc, offset) if struc else None
            if mem:
                set_member_tinfo(struc, mem, 0, tinfo, 0)
        except Exception:
            pass
    return True

def _make_vtbl_ptr_tinfo(vtbl_sid):
    try:
        tinfo = idaapi.tinfo_t()
        if idaapi.guess_tinfo(tinfo, vtbl_sid) == idaapi.GUESS_FUNC_FAILED:
            return None
        tinfo.create_ptr(tinfo)
        return tinfo
    except Exception:
        return None

def _calc_slot_tinfo(func_ea):
    """Pointer-to-function tinfo for a vtable slot, falling back to void* on any miss."""
    if not func_ea:
        return None
    try:
        func_tinfo = idaapi.tinfo_t()
        if idaapi.guess_tinfo(func_tinfo, func_ea) == idaapi.GUESS_FUNC_FAILED:
            voidp = idaapi.tinfo_t()
            voidp.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID))
            return voidp
        ptr_tinfo = idaapi.tinfo_t()
        ptr_tinfo.create_ptr(func_tinfo)
        return ptr_tinfo
    except Exception:
        return None

def create_ida_structs(result):
    if result.get("error"):
        return 0, 0

    classname = result["class"]
    safe      = _safe_id(classname)
    vtbl_created = class_created = 0

    idaapi.begin_type_updating(idaapi.UTP_STRUCT)
    try:
        vtbl_sid = _get_or_create_struc(safe + VTBL_SUFFIX)
        for s in result["slots"]:
            if s["role"] == "pure_virtual":
                member_name, tinfo = "pure_v{}".format(s["index"]), None
            elif s["role"] in ("dtor", "deleting_dtor"):
                member_name = "dtor_v{}".format(s["index"])
                tinfo       = _calc_slot_tinfo(s["ea"]) if s["ea"] else None
            else:
                member_name = _safe_id(s["func_name"])
                tinfo       = _calc_slot_tinfo(s["ea"]) if s["ea"] else None

            if _add_or_skip_member(vtbl_sid, member_name, s["index"] * PTR_SIZE, tinfo):
                vtbl_created += 1
            else:
                idaapi.msg("  [dbg] failed slot {} +{:#x}\n".format(
                    member_name, s["index"] * PTR_SIZE))

        sec_vtbl_sids = {}
        for sec in result.get("secondary_vtables", []):
            ott      = sec["offset_to_top"]
            sec_name = "{}_{}04X{}".format(safe, abs(ott), VTBL_SUFFIX)
            sec_sid  = _get_or_create_struc(sec_name)
            sec_vtbl_sids[ott] = sec_sid
            for s in sec["slots"]:
                mem_name = _safe_id(s["func_name"]) if s["func_name"] else "v{}".format(s["index"])
                tinfo    = _calc_slot_tinfo(s["ea"]) if s["ea"] else None
                _add_or_skip_member(sec_sid, mem_name, s["index"] * PTR_SIZE, tinfo)

        class_sid = _get_or_create_struc(safe)
        if _add_or_skip_member(class_sid, VTBL_MEMNAME, 0, _make_vtbl_ptr_tinfo(vtbl_sid)):
            class_created += 1
        for sec in result.get("secondary_vtables", []):
            ott     = sec["offset_to_top"]
            s_sid   = sec_vtbl_sids.get(ott)
            mem_nm  = "{}_{}04X".format(VTBL_MEMNAME, abs(ott))
            if _add_or_skip_member(class_sid, mem_nm, abs(ott), _make_vtbl_ptr_tinfo(s_sid) if s_sid else None):
                class_created += 1
    finally:
        idaapi.end_type_updating(idaapi.UTP_STRUCT)

    return vtbl_created, class_created

#### method name extraction ###

def _method_name(func_ea, owner, idx):
    """Bare method name for a vtable slot: mangled symbol parse → demangled strip → OwnerClass_vN."""
    if not func_ea:
        return "{}_v{}".format(_safe_id(owner), idx)

    raw = _name(func_ea)
    if raw.startswith("_ZN") or raw.startswith("_ZThn"):
        mangled = re.sub(r"^_ZThn\d+_", "_Z", raw)
        m = re.match(r"^_ZN(.+)E[^E]*$", mangled)
        if m:
            inner, parts, i = m.group(1), [], 0
            while i < len(inner):
                nm = re.match(r"(\d+)([A-Za-z_].*)", inner[i:])
                if not nm:
                    break
                length = int(nm.group(1))
                parts.append(nm.group(2)[:length])
                i += len(str(length)) + length
            if parts:
                last = re.sub(r"<.*", "", parts[-1])
                if last and last.isidentifier():
                    return _safe_id(last)

    dem = idc.demangle_name(raw, idc.get_inf_attr(idc.INF_SHORT_DN)) or ""
    if dem:
        core = dem.split("(")[0].split("::")[-1].strip()
        if core and re.match(r"^[A-Za-z_~]", core):
            return _safe_id(core)

    return "{}_v{}".format(_safe_id(owner), idx)

def _clean_type(tname, size):
    """IDA/Hex-Rays internal type names → readable C++ (e.g. '_QWORD *' → 'uint64_t*')."""
    t = tname.strip()
    for pattern, repl in [
        (r"\b_QWORD\b", "uint64_t"), (r"\b_DWORD\b", "uint32_t"),
        (r"\b_WORD\b", "uint16_t"),  (r"\b_BYTE\b", "uint8_t"),
        (r"\b__int64\b", "int64_t"), (r"\b__int32\b", "int32_t"),
        (r"\b__int16\b", "int16_t"), (r"\b_BOOL\b", "bool"),
        (r"\bunsigned __int64\b", "uint64_t"), (r"\bunsigned __int32\b", "uint32_t"),
        (r"\bunsigned __int16\b", "uint16_t"), (r"\bunsigned __int8\b", "uint8_t"),
        (r"\bsigned __int64\b", "int64_t"),
    ]:
        t = re.sub(pattern, repl, t)
    t = re.sub(r"\s+\*", "*", t)
    if t == "?":
        # no deref/cast/asg context recovered for this field at all — lone single
        # bytes are far more often bools than raw bytes in these structs, and a
        # bare numeric-context field is more often int than pointer.
        t = {1: "bool", 2: "uint16_t", 4: "int32_t", 8: "int64_t"}.get(size, "uint8_t[{}]".format(size))
    elif re.match(r"^_[A-Z]", t) or t in ("void", ""):
        t = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, "uint8_t[{}]".format(size))
    return t

#### formatters ###

def format_header(result):
    if result.get("error"):
        return "// ERROR: {}\n".format(result["error"])

    safe = _safe_id(result["class"])
    lines = [
        "#pragma once",
        "// Auto-generated by Dumper",
        "// class {}  |  ti={:#x}  |  vtable={}".format(
            result["class"], result["ti_ea"] or 0,
            hex(result["vtable_ea"]) if result["vtable_ea"] else "<abstract>"),
        "#include <cstdint>",
        "",
        "class {} {{".format(safe),
        "public:",
    ]

    for s in result["slots"]:
        owner_note = "" if s["owner"] == result["class"] else "  // from {}".format(s["owner"])
        ea_hex = "{:#x}".format(s["ea"]) if s["ea"] else "pure"

        if s["role"] == "pure_virtual":
            lines.append("    virtual void vfunc_{}() = 0;  // [{}] {}{}".format(
                s["index"], s["index"], ea_hex, owner_note))
        elif s["role"] == "dtor":
            lines.append("    virtual ~{}();  // [{}] {} {}".format(
                safe, s["index"], ea_hex, s["func_name"]))
        elif s["role"] == "deleting_dtor":
            lines.append("    // [deleting dtor]  // [{}] {} {}".format(
                s["index"], ea_hex, s["func_name"]))
        elif s["role"] == "deleted_virtual":
            lines.append("    virtual void vfunc_{}() = delete;  // [{}] {}{}".format(
                s["index"], s["index"], ea_hex, owner_note))
        else:
            dem = s.get("demangled", "") or ""
            if "::" in dem and "(" in dem:
                sig = re.sub(r"\s*=\s*0\s*$", "", dem.split("::", 1)[-1]).strip()
                lines.append("    virtual void {}();  // [{}] {}{}".format(
                    sig.split("(")[0], s["index"], ea_hex, owner_note))
            else:
                lines.append("    virtual void {}();  // [{}] {}{}".format(
                    s["func_name"], s["index"], ea_hex, owner_note))

    lines.append("};")

    for sec in result.get("secondary_vtables", []):
        ott      = sec["offset_to_top"]
        sec_safe = "{}_{}04X{}".format(safe, abs(ott), VTBL_SUFFIX)
        lines.append("\n// Secondary vtable  offset_to_top={}  @{}".format(ott, hex(sec["vtable_ea"])))
        lines.append("struct {} {{".format(sec_safe))
        for s in sec["slots"]:
            nm = _safe_id(s["func_name"]) if s.get("func_name") else "v{}".format(s["index"])
            owner_note = "" if s["owner"] == result["class"] else "  // from {}".format(s["owner"])
            lines.append("    void* {};  // [{}] {:#x}  {}{}".format(
                nm, s["index"], s["ea"] or 0, s.get("demangled") or "", owner_note))
        lines.append("};")

    fields = result.get("struct_fields", {})
    if fields and len(fields) > 1:
        lines += ["", "// Struct layout (recovered via AST, heuristic — verify against real headers):",
                   "struct {}_Layout {{".format(safe)]
        offsets, current = sorted(fields.keys()), 0
        for off in offsets:
            if off < current:
                continue
            if off > current:
                lines.append("    char pad_{:x}[{:#x}];  // gap".format(current, off - current))
                current = off

            info = fields[off]
            size = info.get('size', PTR_SIZE)
            tname = _clean_type(info.get('type', 'void*'), size)
            decl = "void** __vftable;" if off == 0 else "{} field_{:x};".format(tname, off)
            lines.append("    {:<40} // {:#x}".format(decl, off))
            current += size
        lines.append("};")
        lines.append("// Total recovered size: {:#x} bytes (lower bound)".format(current))

    return "\n".join(lines)

def format_pseudocode(result):
    if result.get("error"):
        return "// ERROR: {}\n".format(result["error"])

    lines = ["#pragma once", "// Pseudocode: {}  |  Dumper".format(result["class"]), ""]

    def _dump_slots(slots, tag):
        for s in slots:
            if s.get("pseudo"):
                lines.append("// [{}{}] {}  owner:{}".format(tag, s["index"], s["func_name"], s["owner"]))
                lines.append(s["pseudo"])
                lines.append("")
            elif s["ea"] and s["role"] == "func":
                lines.append("// [{}{:3d}] {:#x}  {} — decompile unavailable".format(
                    tag, s["index"], s["ea"], s["func_name"]))

    _dump_slots(result["slots"], "")
    for sec in result.get("secondary_vtables", []):
        lines.append("\n// ── secondary vtable offset_to_top={} ──".format(sec["offset_to_top"]))
        _dump_slots(sec["slots"], "sec{}:".format(abs(sec["offset_to_top"])))

    if not HAS_HEXRAYS:
        lines.append("// Hex-Rays not available.")
    return "\n".join(lines)

#### auto-scan ###

def scan_all_classnames():
    seen, result = set(), []
    for seg_name in (".data.rel.ro", ".data.rel.ro.local", ".rodata"):
        seg = ida_segment.get_segm_by_name(seg_name)
        if not seg:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            nm = ida_name.get_name(ea) or ""
            if nm.startswith("_ZTV"):
                m = re.match(r"^_ZTV(\d+)([A-Za-z_].+)$", nm)
                if m and m.group(2) not in seen:
                    seen.add(m.group(2))
                    result.append(m.group(2))
            nxt = idc.next_head(ea, seg.end_ea)
            ea  = nxt if (nxt != BADADDR and nxt > ea) else ea + PTR_SIZE
    return sorted(result)

#### extract() — per-class pipeline ###

_DELETING_DTOR_RE = re.compile(r"D0Ev$")
_DTOR_RE          = re.compile(r"D[12]Ev$")
# address equality through these proves nothing about inheritance — every class's
# copy of a pure/deleted-virtual trampoline or a byte-identical empty override can
# legitimately (or via ICF) share one address. Never climb ownership through them.
_SHARED_STUB_RE   = re.compile(r"^(__cxa_pure_virtual|__cxa_deleted_virtual|nullsub_\d+)$")

def extract(classname, pseudo=False, structs=False):
    """
    Returns: {class, ti_ea, vtable_ea, slots:[{index,ea,role,owner,func_name,
    demangled,pseudo?}], secondary_vtables:[...], struct_fields:{offset:{size,type}}, error}
    """
    result = {"class": classname, "ti_ea": None, "vtable_ea": None,
              "slots": [], "secondary_vtables": [], "struct_fields": {}, "error": None}

    def _build_slots(vtbl_ea, owner_table, allow_climb):
        slots = []
        for idx, func_ea in enumerate(_raw_slots(vtbl_ea)):
            raw_nm = _name(func_ea) if func_ea else ""

            if func_ea == 0 or raw_nm == "__cxa_pure_virtual":
                role = "pure_virtual"
            elif raw_nm == "__cxa_deleted_virtual":
                role = "deleted_virtual"
            elif _DELETING_DTOR_RE.search(raw_nm):
                role = "deleting_dtor"
            elif _DTOR_RE.search(raw_nm):
                role = "dtor"
            else:
                role = "func"

            # only ordinary virtual functions climb — dtors are always per-class by
            # construction, and shared stubs prove nothing via address equality alone
            climbable = allow_climb and func_ea and role == "func" and not _SHARED_STUB_RE.match(raw_nm)
            owner = slot_owner(owner_table, classname, idx, func_ea) if climbable else classname

            slot = {
                "index": idx, "ea": func_ea or None, "role": role, "owner": owner,
                "func_name": "" if role == "pure_virtual" else _method_name(func_ea, owner, idx),
                "demangled": _demangled(func_ea) if func_ea else "",
            }

            if func_ea:
                if pseudo and role == "func":
                    slot["pseudo"] = _decompile(func_ea)
                if structs:
                    _scan_struct_fields(func_ea, result["struct_fields"])

            slots.append(slot)
        return slots

    ti_ea = find_typeinfo(classname)
    if ti_ea == BADADDR:
        # no RTTI — fall back to the vtable directly. No ancestor chain exists
        # without a _ZTI, so ownership can never climb on this path.
        vtbl_ea = find_vtable_direct(classname)
        if vtbl_ea == BADADDR:
            result["error"] = "no _ZTI or _ZTV found for '{}'".format(classname)
            return result
        result["vtable_ea"] = vtbl_ea
        result["slots"] = _build_slots(vtbl_ea, owner_table=[], allow_climb=False)
        if structs:
            result["struct_fields"].setdefault(0, {"size": PTR_SIZE, "type": "void*"})
        return result

    result["ti_ea"] = ti_ea
    chunks = vtable_chunks(ti_ea)
    if not chunks:
        result["error"] = "no usable vtable chunks for '{}'".format(classname)
        return result

    result["vtable_ea"] = chunks[0][1]
    owner_table = _ancestor_owner_table(ti_ea, ott=0)

    result["slots"] = _build_slots(result["vtable_ea"], owner_table, allow_climb=True)
    for ott, vtbl_ea in chunks[1:]:
        sec_table = _ancestor_owner_table(ti_ea, ott=ott)
        result["secondary_vtables"].append({
            "offset_to_top": ott, "vtable_ea": vtbl_ea,
            "slots": _build_slots(vtbl_ea, sec_table, allow_climb=True)})

    if structs:
        result["struct_fields"].setdefault(0, {"size": PTR_SIZE, "type": "void*"})

    return result

#### IDA plugin ###

class _ExtractForm(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, r"""STARTITEM 0
Dumper
Blank Classes = scan every _ZTV.
<Classes      :{cnClasses}>
<Output folder:{cnOutFile}>
<##Options##Decompile pseudocode (Hex-Rays):{cPseudo}>
<Recover struct fields + IDA structs:{cStructs}>{cGroup}>
""", {
            'cnClasses': idaapi.Form.StringInput(swidth=56),
            'cnOutFile': idaapi.Form.DirInput(swidth=56),
            'cGroup':    idaapi.Form.ChkGroupControl(("cPseudo", "cStructs")),
        })


class VtableExtractorPlugin(idaapi.plugin_t):
    flags         = idaapi.PLUGIN_UNL
    comment       = "Extract vtables, structs, and pseudocode from RTTI"
    help          = "Ctrl-Shift-V"
    wanted_name   = "Dumper5000"
    wanted_hotkey = "Ctrl-Shift-V"

    def init(self):  return idaapi.PLUGIN_OK
    def term(self):  pass

    def run(self, _arg):
        f = _ExtractForm()
        f.Compile()
        f.cPseudo.checked = True
        f.cStructs.checked = True
        if not f.Execute():
            f.Free(); return

        classes_raw = f.cnClasses.value.strip()
        out_dir     = f.cnOutFile.value
        do_pseudo, do_structs = f.cPseudo.checked, f.cStructs.checked
        f.Free()

        if not out_dir:
            idaapi.warning("Pick an output folder."); return
        if not os.path.isdir(out_dir):
            idaapi.warning("Directory not found: {}".format(out_dir)); return

        classnames = [c.strip() for c in classes_raw.split(",") if c.strip()] or scan_all_classnames()
        if not classnames:
            idaapi.warning("No classes found (no _ZTV symbols)."); return

        written = structs_made = struct_mems = 0
        idaapi.show_wait_box("Extracting — 0 / {}".format(len(classnames)))
        prev_batch = idc.batch(1)  # auto-answer Hex-Rays warning dialogs instead of stalling per-class
        try:
            for i, cn in enumerate(classnames):
                if idaapi.user_cancelled(): break
                idaapi.replace_wait_box("Extracting — {} / {}  —  {}".format(
                    i + 1, len(classnames), cn))

                r = extract(cn, pseudo=do_pseudo, structs=do_structs)
                idaapi.msg("[Dumper] {}: {}\n".format(
                    cn, r.get("error") or "{} slots".format(len(r["slots"]))))
                if r.get("error"):
                    continue

                safe = _safe_id(cn)
                try:
                    open(os.path.join(out_dir, safe + ".h"), "w", encoding="utf-8").write(format_header(r))
                    written += 1
                except Exception as ex:
                    idaapi.msg("  WRITE ERROR {}.h: {}\n".format(safe, ex))

                if do_pseudo:
                    try:
                        open(os.path.join(out_dir, safe + "_pseudo.h"), "w",
                             encoding="utf-8").write(format_pseudocode(r))
                        written += 1
                    except Exception as ex:
                        idaapi.msg("  WRITE ERROR {}_pseudo.h: {}\n".format(safe, ex))

                if do_structs:
                    try:
                        vm, cm = create_ida_structs(r)
                        structs_made += 1
                        struct_mems  += vm + cm
                    except Exception as ex:
                        idaapi.msg("  STRUCT ERROR {}: {}\n".format(safe, ex))
        finally:
            idc.batch(prev_batch)
            idaapi.hide_wait_box()

        idaapi.info("Done.\n{} class(es)\n{} file(s) written\n{} struct(s) ({} members)\n{}".format(
            len(classnames), written, structs_made, struct_mems, out_dir))


def PLUGIN_ENTRY():
    return VtableExtractorPlugin()
