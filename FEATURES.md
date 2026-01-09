# Features roadmap (Disassembly → C reconstruction)

This document captures the set of features that would make it significantly easier to reconstruct `BLST.EXE` (and similar DOS4GW LE binaries) into C from the disassembly.

The intent is not to build a full decompiler immediately, but to add high-leverage, best-effort analyses that:
- reduce “mystery blocks”
- stabilize naming
- surface control-flow structure and dataflow meaning

## Reconstruction workflow (target)

A practical “disassembly → C” workflow looks like:

1. Build call graph and locate top-level entrypoints (startup/init, main loop, parser/dispatcher).
2. For each function, recover stack frame + arguments + calling convention.
3. Lift to a simple IR (3-address / SSA-ish) for local expression simplification.
4. Structure control flow (if/else, loops, switch) to reduce gotos.
5. Infer types: structs/fields, arrays, enums, bitfields, vtables.
6. Name things based on usage and API interactions.

## Feature backlog

### 1) Function signatures & calling conventions
- Infer calling convention per function (callee cleanup, typical patterns).
- Infer argument count and “kind” (scalar vs pointer vs size).
- Infer return value usage (bool/error/pointer) via downstream use.
- Detect out-parameters (`lea reg, [local]` passed to call; later written).

### 2) Stack frame reconstruction (locals/args)
- Per-function stack layout (locals, args, sizes, alignment).
- Local liveness splitting (when the same stack slot is reused for different meanings).
- Address-taken locals (`&local_XX`) tracked as proper “variables” (not anonymous memory).

### 3) Expression lifting (dataflow)
- Cross-basic-block register/value propagation (not just local hints).
- Constant propagation + simplification (fold masks/shifts and common idioms).
- Lightweight alias tracking / memory SSA for "ptr + field" accesses.

### 4) Struct / field recovery
- Group inferred pointer bases into per-type structs (best-effort field table aggregation for `ptr_XXXXXXXX` is implemented).
- Field type inference (partial): infer access width (byte/word/dword) and mark some fields as pointer-like (`ptr`) based on usage.
- Detect array strides (best-effort): mark fields as array-indexed (`arr*2/4/8`) when accessed via `base+idx*scale+disp`.
- Improve vtable detection and slot labelling.

### 5) Control-flow structuring
- Normalize decision trees into a single `switch(var)` summary (cases + default + ranges).
- Loop detection (`while`/`do`/`for`) and induction variable hints. (implemented: back-edge + basic induction heuristic)
- State-machine recognition (dispatch on a state variable, transition summaries).

### 6) Role naming (functions/blocks/variables)
- Per-function role classification: parser, loader, VGA init, mixer, blit, etc.
- Per-block role: error path, init-once, critical section, bounds check, fast path.
- Propagate roles into symbols (best-effort, reversible).

### 7) Better API surface modeling
- Enrich INT21/INT31 patterns at call sites (open/read/close sequences, DPMI alloc/free pairing).
- Recognize DOS4GW/Watcom runtime idioms (startup thunks, error handlers).

### 8) Data segment understanding
- Cluster globals into “struct-like” groups vs scattered singletons.
- Detect read-only tables (jump tables, command tables, keymaps, palettes).
- Emit table summaries (element size, count, consumers).

### 9) Output format tuned for C
- Per-function “C sketch header”: guessed prototype, locals/args, key globals/strings, ports/interrupts. (implemented: compact `C:` line)
- Stable per-function variable mapping (register role stabilization: `ebx=cursor`, etc.).
- Def-use summaries for key variables.

### 10) Optional: IR export
- Export a simple IR alongside asm to make C generation mechanical.
- IR should expose:
  - normalized locals/args
  - structured control flow metadata
  - typed memory ops (`p->field_XX`, array indexing)

## Implementation sequence (starting point)

We’ll start with the most immediate payoff for C reconstruction:

1. Infer local variable aliases from ASCII token dispatch switches (e.g., `switch(al)` decision trees) and rewrite `local_XX` to meaningful per-function aliases.
2. Extend switch summaries to include per-case “role” actions (INT/I/O/local setup) (already in progress).
3. Expand alias inference beyond switches (out-params, flags, counters, indices).
