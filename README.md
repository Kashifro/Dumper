# Dumper5000

RTTI based vtable extraction plugin

## What it does

* virtual methods
* approx structs
* pseudocodes
* multiple inheritance vtables
* compare two vtables

### IDA Side

* creates vtable structs
* creates class structs
* assigns function pointer types
* updates local type database

### Required

* RTTI present in target binary

## Usage

Launch plugin:

```text
Ctrl + Shift + V
```

### Extract Specific Classes

Enter class names:

```text
HoverTextRenderer
ClientInstance
MinecraftGame
```

Multiple classes:

```text
HoverTextRenderer,ClientInstance,MinecraftGame
```

### Scan Entire Binary

Leave Classes field empty.

Plugin will scan all discovered `_ZTV` symbols.

### Diff Two Classes

Fill:

```text
Classes: ClassA
Diff Against: ClassB
```

Produces:

```text
ClassA_vs_ClassB.diff.txt
```
