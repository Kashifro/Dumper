# Dumper5000
RTTI based vtable extraction plugin

## What it does
* **Virtual methods** - walks RTTI to recover every vtable slot,
  and resolves which base class actually owns a shared slot via the ancestor
  chain
* **Approx structs** - heuristic struct field layouts, it's a lower bound, not a guarantee
* **Pseudocode** - decompilation of every resolved slot, written
  alongside the header
* **Multiple inheritance vtables** - secondary vtables get extracted as their own **struct**
* ~~Compare two vtables~~ — removed; this doesn't have a diff feature

### IDA side
* Creates vtable structs
* Creates class structs
* Assigns function pointer types to vtable members
* Updates the local type database

### Required
* RTTI present in the target binary for full extraction with
  ownership info.

## Usage
```text
Ctrl + Shift + V
```
Leave **Classes** blank to scan every `Vtable` in the binary, or give a
comma separated list eg flat (`HoverRenderer`), namespaced (`mce::TextureGroup`),
or pre-mangled (`N3mce12TextureGroupE`) all work. Pick an output folder; one
`.h` (and `_pseudo.h`, if pseudocode is enabled) gets written per class.
