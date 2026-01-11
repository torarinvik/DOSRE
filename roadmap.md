# DOSRE Roadmap (Easiest → Hardest)

This roadmap orders work items from [reverse-engineering-checklist.md](reverse-engineering-checklist.md) by **implementation difficulty in DOSRE** (given current code), not by theoretical RE difficulty.

Notes on current baseline (already present in the repo):
- LE disassembly pipeline exists (object/page reconstruction, partial fixup parsing/annotation, insights, pseudo-C decompiler).
- Call summaries / CFG-ish building exists internally.
- Recent addition: call graph export (DOT/JSON) via `-LECALLGRAPHDOT` / `-LECALLGRAPHJSON`.

---

## Phase 0 — Paper cuts + “make it observable” (very easy)

1) **Output a single structured “LE report”** (JSON)
- Includes: header fields, object list (flags/sizes/bases), entry linear, import modules, fixup stats.
- Why: makes every later feature testable without scraping text.

2) **Export CFG as DOT for a chosen function**
- CLI idea: `-LECFGDOT func_XXXXXXXX out.dot` (or `-LECFGDOT outDir` for top N).
- Uses existing basic-block/pred logic.

3) **Improve per-run analysis exports**
- Extend the existing callgraph JSON to include: roots, strongly connected components (SCCs), top fan-in/out, orphan funcs.

4) **Add deterministic “analysis fixtures”**
- Small checked-in tests that run DOSRE on a tiny sample and assert the exports are stable.

---

## Phase 1 — Correctness improvements that unblock everything (easy → medium)

5) **Fixup decoding hardening (bread-and-butter)**
- Expand LE fixup parsing beyond the current best-effort.
- Add: classification, addends/chains, selector/pointer forms.
- Output: a normalized fixup table export.

6) **Import map export + usage xrefs**
- Provide `imports.json` and “where called” references.

7) **Entry point + thunk discovery improvements**
- Better detection for indirect call tables / thunk vectors.

---

## Phase 2 — Code vs data truth + function boundaries (medium)

8) **Reachability-based code marking**
- Build a reachable set from entrypoints using calls/jumps (incl. jump tables).
- Mark remaining regions as data candidates.

9) **Jump table detection robustness**
- Handle stride/element-size, bounds inference, and “switch chains”.

10) **Function boundary refinement**
- Detect prolog/epilog patterns and split/merge wrongly grouped functions.

Deliverable: fewer “junk functions” and fewer missing labels in pseudo-C output.

---

## Phase 3 — Decompiler stabilization (medium → hard)

11) **Stack frame reconstruction (locals/args)**
- Stable var naming across blocks.
- Address-taken locals tracked as true variables.

12) **Cross-basic-block value propagation**
- Already some state propagation exists; make it systematic and measurable.
- Add lightweight constant propagation and simplification.

13) **Flags semantics and conditional correctness**
- Make carry/overflow-based branches first-class in the pseudo-C lowering.
- Avoid “unknown jae/…” fallbacks by modeling flag state.

---

## Phase 4 — Data/Type recovery (hard)

14) **Struct/field recovery pipeline**
- Aggregate per-pointer-base field stats into candidate struct types.
- Infer field widths/types; detect arrays; vtable slots.

15) **Calling convention + signature inference**
- Estimate arg count, return usage, out-params.

---

## Phase 5 — Verification harness + platform API surface (hard, but high value)

16) **API surface annotation (DOS/BIOS/DPMI)**
- Identify and annotate `int 31h`, `int 21h`, `int 10h`, port I/O callsites.
- Use the existing interrupt DB + patterns from the checklist addendum.

17) **Behavior trace / regression harness**
- Scriptable runs (DOSBox-X) producing comparable traces.
- Checkpoints: early boot, resource loads, first frame, exit.

---

## Phase 6 — Rebuild-to-LE tooling (very hard / long-term)

18) **Emit assembler-acceptable sources with relocations**
- Convert absolute addresses to symbols.
- Preserve object ordering/flags.

19) **Repack/relink into LE container**
- Generate LE header/tables/imports/fixups correctly.
- This is the “endgame” for byte/format-faithful builds.

---

## Suggested next step (pick one)

- If you want **fast wins this week**: implement Phase 0 items (LE report + CFG export).
- If you want **correctness for EURO96**: start Phase 1 fixup decoding hardening.

When you tell me which direction you want, I’ll implement the next phase directly (CLI flags + output files + minimal tests where appropriate).
