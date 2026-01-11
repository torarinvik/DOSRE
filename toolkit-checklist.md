# DOSRE Toolkit Checklist (derived from reverse-engineering-checklist.md)

Goal context: DOS/4GW-style MZ stub → LE payload → 32-bit protected mode via DPMI, targeting **behavior-identical** reconstruction.

This file restates the source checklist as **actionable engineering tasks for DOSRE** (parser → disassembly → analysis → decompile → verification tooling).

## 0) Target + success criteria
- [ ] Decide target: behavior-identical vs byte-identical.
- [ ] Define “done” criteria for a title (exit code, I/O patterns, first frame, etc.).
- [ ] Record deterministic reference environment (DOSBox-X settings, DPMI host, cycles, devices).

## 1) Acquisition + preservation
- [ ] Hash and archive original EXE(s) + all runtime deps/assets.
- [ ] Baseline “golden run” artifacts: logs, screen captures, key file outputs.

## 2) Format parsing (MZ + LE)
- [ ] Parse MZ header/stub robustly (incl. new-header pointer / overlay patterns).
- [ ] Confirm/parse LE header essentials (objects, pages, entry, imports, fixups).
- [ ] Support “unwrap” patterns (already present: BW overlay unwrapping) + add a generic report for container quirks.

## 3) Object/page reconstruction
- [ ] Reconstruct object linear images from pages.
- [ ] Track zero-fill pages (BSS) and virtual-size vs file-size.
- [ ] Preserve/record alignment + per-object attributes (RX/RW) for downstream modeling.

## 4) Fixups / relocations / imports (the truth layer)
- [ ] Parse fixups comprehensively (internal, import, selector, pointer, chain/addend).
- [ ] Build import map (module/proc names/ordinals) and expose as structured output.
- [ ] Provide canonical “relocation expression” representation for asm/C emitters.

## 5) Memory model + calling conventions
- [ ] Determine 16-bit vs 32-bit objects and annotate mixed-mode islands.
- [ ] Model selectors/segment usage (DS/ES/SS/CS semantics map).
- [ ] Infer calling convention/arg count/ret usage per function (best-effort).

## 6) Disassembly correctness guarantees
- [ ] Ensure disassembly is done with fixups applied/visible (mis-disasm avoidance).
- [ ] Mark all entry points (LE entry + known exports/thunks + callback entry points).
- [ ] Build cross-reference index (calls/jumps/data xrefs) as structured data.
- [x] Export LE call graph (best-effort):
	- `-LECALLGRAPHDOT <file.dot>`
	- `-LECALLGRAPHJSON <file.json>`

## 7) Code vs data separation
- [ ] Reachability-based code marking from entry points + call/jump graph.
- [ ] Identify data regions by refs (fixup targets, tables, string pools).
- [ ] Jump table detection: bounds/stride correctness; mixed code/data handling.

## 8) Control-flow + semantics recovery (minimum viable, but correct)
- [ ] Function boundary detection improvements.
- [x] CFG construction per function; basic block + preds/succs (best-effort) + exports:
	- `-LECFGDOT <file.dot>` (per-function; uses `-LEFUNC` if provided, else entry)
	- `-LECFGALLDOT <file.dot>` (whole-program index)
	- `-LECFGALLJSON <file.json>` (whole-program index)
- [ ] Loop recognition and stable loop headers.
- [ ] Flag-sensitive correctness (carry/overflow dependencies, conditional moves/sets).

## 9) C/IR reconstruction outputs
- [ ] Emit a stable pseudo-C skeleton with gotos (existing), reduce placeholders.
- [ ] Stack-frame reconstruction (locals/args) and reuse-splitting.
- [ ] Expression lifting (constant propagation, simplification, alias tracking).
- [ ] Struct/field recovery (ptr bases, field widths, arrays, vtables).
- [ ] Optional: export a simple IR alongside asm/C (SSA-ish 3-address).

## 10) Non-code payload understanding (if relevant)
- [ ] Resource/string table extraction and stable symbolization.
- [ ] Resident/non-resident name handling.
- [ ] Embedded debug/info detection (optional).

## 11) Re-link / rebuild into an executable container (hard)
- [ ] Produce assembler-acceptable sources with link-time relocations.
- [ ] Recreate entry table + imports + fixup metadata.
- [ ] Preserve object ordering/flags/alignment.

## 12) Static validation tooling
- [ ] Re-parse reconstructed output and validate tables/ranges.
- [ ] Structural diff vs original (objects/flags/entry/import/fixups).

## 13) Behavioral equivalence testing harness
- [ ] Scriptable DOSBox-X runs (inputs, env settings, expected artifacts).
- [ ] Instrumentation hooks: log DPMI/DOS/BIOS calls, file I/O, ports.
- [ ] Snapshot checks (selective memory checksums at checkpoints).

## 14) Special cases (“dragons”)
- [ ] Self-checksums / integrity checks detection + reporting.
- [ ] Self-modifying code detection (writes into RX pages / exec from RW).
- [ ] Uninitialized memory dependence detection (heuristic warnings).

## 15) Packaging + documentation
- [ ] Document mapping: objects, entry points, imports, fixups, selector model.
- [ ] Keep a regression harness and “known good” outputs per title.

---

# DOS/4GW-specific addendum (from the checklist’s A–L sections)

## A) Baseline reference run (DPMI host + timing)
- [ ] Record DPMI host choice and keep fixed for comparisons.
- [ ] Record CPU/timing configuration used for golden traces.

## B–D) Parser + fixups + selector semantics
- [ ] Emit a “selector ledger” view: when selector-like values appear and how they relate to objects.
- [ ] Distinguish and label selector fixups and far pointers.

## E–F) Entry chain + platform API surface
- [ ] Identify extender glue vs program logic (startup chain).
- [ ] Catalog `int 31h` / `int 21h` / `int 10h` / port I/O callsites.

## K–L) Verification + done criteria
- [ ] Provide debugger-friendly trace output templates (DPMI call logs etc.).
- [ ] Define per-title behavioral checkpoints and run them continuously.
