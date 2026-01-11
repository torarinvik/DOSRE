## 0) Decide your target: byte-identical vs behavior-identical

1. **Behavior-identical** (your goal): same runtime behavior across realistic environments.
2. **Byte-identical** (hard mode): same bytes on disk (usually requires recreating link order, timestamps, padding, checksum quirks, stub bytes, etc.).

---

## 1) Acquisition and preservation

1. **Capture the exact input**
   * Copy original EXE as-is (no “fixing”, no virus scanner rewriting).
   * Record file hash (CRC32/SHA256).
2. **Collect runtime dependencies**
   * Extender runtime (DOS/4GW, DOS/32A, CWSDPMI, etc.), plus versions.
   * Any external files the program loads (DAT, CFG, overlays, etc.).
3. **Establish reference environment**
   * Pick a deterministic emulator/VM setup (DOSBox-X preferred for debugging).
   * Record CPU type, cycles, EMS/XMS, DPMI provider, sound, VESA, etc.
4. **Baseline behavioral trace (for later matching)**
   * Known-good inputs + expected outputs.
   * Golden runs: logs, file outputs, screen captures, network (if any).

---

## 2) Identify and parse the executable format(s)
LE often sits behind a DOS MZ stub, so you parse both.

1. **Parse the MZ header/stub**
   * Verify `MZ` header, locate the “new header” pointer (`e_lfanew`-like field).
   * Preserve stub bytes if you want faithful packaging.
2. **Confirm LE and read LE header**
   * Validate `LE` signature and byte order.
   * Extract key header fields:
     * Object table offset/count
     * Page size, page table offset
     * Fixup/relocation tables
     * Entry table
     * Import module/procedure tables
     * Resource tables (if present)
     * Resident/non-resident name tables
     * Stack/heap sizes, initial CS:EIP/SS:ESP equivalents
3. **Determine execution model**
   * Pure LE app? LE loader required? Extender present?
   * DPMI usage vs VCPI, protected-mode assumptions, descriptor tables, etc.
4. **Catalog “payload layout”**
   * Objects (segments), their flags: code/data, read/write/execute, 16/32-bit, conforming, etc.
   * Pages: map object→pages→file offsets, handle zero-fill pages.

---

## 3) Extract raw object data correctly

1. **Reconstruct each object’s linear image**
* For each object:
     * Pull all mapped pages from the page table.
     * Insert zero-filled pages where indicated.
     * Respect object virtual size vs file size.
2. **Preserve alignment/padding semantics**
   * Page size alignment (often 4K) matters for faults and self-checks.
3. **Detect overlays / external paging**
   * Some extenders or apps implement their own overlay paging beyond LE.

---

## 4) Extract and decode fixups (relocations) and imports

This is the part that makes “just disassemble it” fail.

1. **Parse fixup records**
   * For each fixup:
     * Source location (object+offset)
     * Fixup type (16/32, selector, offset, pointer, etc.)
     * Target: internal object, imported module/proc, or entry table ordinal
     * Addends / chain behavior
2. **Build an import map**
   * Module list, procedure names/ordinals.
   * Identify known APIs: DPMI interrupts, extender helper calls, DOS calls.
3. **Normalize relocation expressions**
   * Decide how you will represent them in assembly:
     * As `EXTERN` symbols + linker relocations, or
     * As explicit tables applied by your own loader code (usually worse).

---

## 5) Establish memory model + calling conventions

1. **Determine 16-bit vs 32-bit code**
   * LE can contain 16-bit segments but typically 32-bit protected-mode code.
2. **Figure out segment/selector meaning**
   * In LE, “segments” are objects; at runtime they become selectors/descriptors.
3. **Identify calling conventions**
   * cdecl/stdcall/pascal, register calling, extender-specific ABI.
4. **Model the program’s “environment contract”**
   * What it assumes about:
     * DPMI host, A20, LDT/GDT behavior
     * Interrupt vectors
     * Real-mode callbacks
     * DOS memory layout, PSP, environment block

---

## 6) Disassembly setup (make the disassembler tell the truth)

1. **The dissassembler must**
    * Creates segments/objects
    * Applies fixups
    * Creates imports and entry points
2. **Load with correct base assumptions**
   * Page/object mapping, default operand size, segment attributes.
3. **Create symbols for LE structures**
   * Entry table, import tables, fixup sections, resources.
4. **Mark all entry points**
   * Main entry + exported entries + callback entry points used indirectly.

---

## 7) Turn “bytes” into “code vs data” accurately

1. **Code/data separation pass**
   * Identify code regions: reachable from entry points + jump tables.
   * Identify data regions: referenced by address, relocation targets, tables.
2. **Handle jump tables and switch dispatch**
   * Create correct table bounds and element sizes.
3. **Handle mixed code/data**
   * Some old compilers embed data in code segments.
4. **Handle self-modifying / unpacking code**
   * Detect runtime writes into code pages or decompression stubs.

---

## 8) Control-flow + semantics recovery (minimal, but enough)

You don’t need “nice decompilation”, but you *do* need correctness.

1. **Reconstruct function boundaries**
   * Prolog patterns, call graphs, exception/unwind constructs (if any).
2. **Recover stack frames where possible**
   * Identify local variables, calling convention effects.
3. **Identify critical low-level behaviors**
   * Segment register usage
   * Far/near calls (in 16-bit parts)
   * Inline interrupt calls (int 21h, int 10h, DPMI int 31h)
   * Port I/O (in/out), DMA, timer reads
4. **Document undefined/CPU-specific behavior**
   * Reliance on flags, uninitialized reads, timing loops.

---

## 9) Reconstruct buildable assembly source

This is where most projects die: you must produce *assembler-acceptable* structure.

1. **Pick assembler + linker that can target your desired format**
   * Options:
     * Rebuild to **LE** (hard, toolchain support varies)
     * Rebuild to **a different extender format** but same behavior (often easier)
2. **Define the memory/segment/object layout**
   * Object ordering, sizes, attributes (RX/RW), alignment.
3. **Create symbol map**
   * For every cross-reference: label names, segment-qualified symbols.
4. **Rewrite relocations as link-time fixups**
   * Replace absolute addresses with symbolic references.
5. **Recreate entry table and export(if used)**
   * Ensure ordinals match if other modules call into it.
6. **Recreate import definitions**
   * Match module/proc names and ordinals expected at runtime.
7. **Handle compiler “weirdness”**
   * Thunks, tailcalls, align nops, “assume” directives, FPU init patterns.
8. **Recreate data sections exactly**
   * Struct packing, padding bytes, alignment.
   * Floating-point constants exact bit patterns.
   * Jump tables exact layout.
9. **Preserve sentinel bytes / canaries used by integrity checks**
   * Some programs checksum their own code or data.

---

## 10) Recreate non-code payloads embedded in LE

1. **Resources (if present)**
   * Parse resource table and extract entries.
   * Re-embed with same IDs/types if the program expects them.
2. **Resident/non-resident names**
   * Preserve if relied upon for module lookup/debugging.
3. **Debug info (optional)**
   * Usually not required for behavior, but some apps detect it.
4. **Relocation/fixup metadata**
   * Must be correct or loader will patch wrong addresses.

---

## 11) Re-link into an executable container

1. **Construct DOS MZ stub (if needed)**
   * Same stub message/behavior, same termination path.
2. **Generate LE header + tables**
   * Object table with correct flags
   * Page table with correct mapping
   * Fixup sections built from your link relocations
   * Import tables
   * Entry table
3. **Match alignment and sizes**
   * Page-size rounding, object virtual sizes, heap/stack values.
4. **Match loader expectations**
   * Extender may expect certain object numbers or flags.

---

## 12) Validate on-disk structure correctness

1. **Static validation**
   * Re-parse your new LE and confirm:
     * All offsets in-range
     * Tables consistent
     * Page mapping correct
     * Fixups point to valid targets
2. **Diff structural intent**
   * Compare object sizes/flags, entry points, import lists vs original.
3. **Sanity-run under a loader**
   * Confirm it starts and reaches expected early initialization.

---

## 13) Behavioral equivalence testing (the “prove it” step)

1. **Deterministic test suite**
   * Same inputs, same environment, same command line.
2. **I/O equivalence**
   * Files created/modified, stdout/stderr, exit codes.
3. **Timing sensitivity**
   * If timing loops exist, compare under same cycles or patch to time sources.
4. **Instrumentation**
   * Use debugger breakpoints on:
     * DPMI calls
     * DOS interrupts
     * File I/O functions
     * Sound/graphics init
   * Compare call sequences and key parameters.
5. **State snapshots**
   * Memory checksums at key checkpoints (careful with nondeterminism).

---

## 14) Handle the nasty special cases

These are common in DOS extender land.

1. **Self-checksums / anti-tamper**
   * They may hash code pages; your rebuild must match those bytes or patch logic.
2. **Self-modifying code**
   * Must preserve page permissions and exact write locations.
3. **Uninitialized memory dependence**
   * Old code sometimes “works” because memory happens to be zeroed.
4. **Exception/interrupt trickery**
   * Custom handlers, real-mode callbacks, protected-mode IDT hooks.
5. **FPU/CPU quirks**
   * 387 vs emulation differences, undefined flags, division edge cases.

---

## 15) Final packaging + documentation

1. **Ship the exact runtime bundle**
   * Same extender/DPMI host versions if required.
2. **Document the reconstruction**
   * Mapping of objects, entry points, imports, fixups.
   * Any intentional behavior-preserving deviations.
3. **Regression harness**
   * Scriptable runs for DOSBox-X to validate future changes.

---

### Practical reality check (the wise-cruel footnote)

If the goal is “exact same behavior”, you usually succeed by being obsessive about:

* **fixups/imports**,
* **segment/object attributes**, and
* **any self-integrity behavior**.

Most “it almost works” failures are: one selector fixup wrong, one object marked writable vs not, one alignment difference changing a checksum or a pointer table.

 **Watcom + DOS/4GW (or compatible) LE**. Think mid-90s DOS games/tools: MZ stub → LE payload → 32-bit protected mode via DPMI.

## What a typical DOS/4GW LE looks like

* **MZ stub** that runs in real mode and boots the extender.
* **LE payload** with multiple objects:
  * at least one **32-bit code** object (RX),
  * one **data** object (RW),
  * sometimes **bss/zero-fill** object(s),
  * sometimes tiny **16-bit** helper object(s) (less common).
* Imports/fixups primarily for:
  * **DPMI** (via `int 31h`) and real-mode callbacks,
  * **DOS services** (`int 21h`), BIOS (`int 10h`), ports, etc.,
  * extender runtime glue (often not “imports” like PE DLLs; it’s more “calls into known vectors / thunks / int gates”).

---

# A) Baseline: lock down your reference run (DOS/4GW-specific)

1. **Pick DPMI host and keep it fixed**

   * DOSBox-X internal DPMI vs CWSDPMI vs Windows NTVDM style hosts behave differently.
2. **Fix the CPU + timing**

   * Same cycles/core settings; DOS/4GW programs often have tight loops / timer heuristics.
3. **Record the program’s early boot behavior**

   * First 1–3 seconds: interrupts installed, DPMI allocations, selector setup, VESA/SB init, file opens.

---

# B) Parse: MZ stub + LE header, with “DOS/4GW expectations”

1. **MZ stub analysis**
* Confirm it’s a DOS/4GW-style launcher (many stubs print “This program requires…” or silently chainload).
* Note if the stub does:
    * checks CPU (386+),
    * checks DPMI presence,
    * decompresses/relocates something before jumping into LE.
2. **LE header essentials**
   * Object table: count, flags, virtual size.
   * Page size and page table.
   * Entry table offset/size.
   * Fixup table locations.
3. **Detect “packed” vs “plain”**

   * Some DOS/4GW-era tools were packed (PKLITE/DIET/EXEPACK-ish variants, or custom).
   * If packed, disassemble the *unpacked* image (via runtime dump).

---

# C) Reconstruct object images correctly (the “page truth” step)

1. **For each object**

   * Rebuild its linear bytes from LE pages.
   * Respect:

     * page table mapping,
     * zero-fill pages (bss),
     * virtual size > file size.
2. **Track object attributes**

   * RX vs RW matters (self-modifying code, guard pages, integrity checks).
3. **Preserve alignment**

   * DOS/4GW programs sometimes assume 4K page boundaries for tables and fault behavior.

---

# D) Fixups + selectors: the DOS/4GW pain point

DOS/4GW protected-mode code tends to be full of “address that becomes valid only after fixups”.

1. **Parse fixup records and classify**

   * **Internal fixups**: object→object references (most common).
   * **Selector fixups**: places where a selector value gets patched in.
   * **Pointer fixups**: offset+selector pairs, far pointers, etc.
2. **Build a “selector semantics map”**

   * Identify which objects become which selectors at runtime.
   * Identify common segment registers usage patterns:

     * `DS`/`ES` typically point at data selector,
     * `CS` code selector,
     * `SS` stack selector.
3. **Turn fixups into symbolic expressions**

   * In your rebuilt assembly, never hardcode post-fixup absolute linear addresses.
   * Use symbols and let the linker emit relocations / fixups.

---

# E) Find the real entry and the DOS/4GW init chain

This matters because the “program entry” is often *not* the game’s `main()` directly.

1. **Entry table**

   * Identify initial CS:EIP (or equivalent) from LE header/entry table.
2. **DOS/4GW C runtime patterns (common Watcom)**
   You’ll often see:

   * stack setup,
   * `__CHK`, `__STK`, or stack probes,
   * FPU init (`fninit`),
   * zeroing `.bss`,
   * copying `.data` init,
   * then calling something like `_cstart_` / `__start` → `main`.
3. **Separate “extender glue” from “program logic”**

   * Extender glue: selector setup, DPMI allocations, real-mode callback registration.
   * Program logic: actual app/game initialization.

---

# F) Identify the “platform API surface” used by the program

For behavior matching, you need to preserve these call sites and their conventions.

### 1) DPMI (`int 31h`) patterns to catalog

Make a table of which functions are used, where, and expected return values.

Common ones you’ll see:

* Allocate/free LDT descriptors (selectors)
* Set descriptor base/limit/access rights
* Allocate/free linear memory blocks
* Map physical memory (less common)
* Lock/unlock linear regions (for DMA / interrupts)
* Get/set interrupt vectors
* Real-mode callbacks + simulated interrupts

Even if you don’t name the functions perfectly, you must preserve:

* register conventions,
* carry flag meaning,
* expected error codes.

### 2) DOS (`int 21h`) patterns

* File open/read/write/seek (AH=3Dh/3Fh/40h/42h etc.)
* Memory (DOS conventional) calls if they still use any real-mode allocations
* Environment/PSP queries
* Time/date, keyboard, device I/O

### 3) BIOS + hardware I/O

* `int 10h` VESA/VGA setup
* `int 16h` keyboard
* Port I/O for sound (SB/OPL), timer, joystick
* DMA programming (if they go that low)

**Why this list matters:** rebuilding changes layout; if a callsite used a hardcoded pointer expecting a fixup, you must reproduce the fixup and pointer format exactly.

---

# G) Disassembly workflow tuned for DOS/4GW LE

1. **Use a loader that applies LE fixups**

   * If your tool doesn’t, you’ll mis-disassemble “relocated pointers” as junk constants.
2. **Create segments per object**

   * Code object(s), data object(s), bss object(s).
3. **Auto-mark entry points and thunk tables**

   * Many DOS extenders have “import-ish” thunk stubs or jump vectors.
4. **Hunt for jump tables**

   * Watcom codegen loves switch tables; get bounds right.

---

# H) Reassembly strategy that actually works (DOS/4GW flavor)

You have two realistic paths:

## Path 1: Rebuild as LE again (behavior match, format match)

Harder toolchain-wise, but conceptually clean.

1. **Choose an assembler/linker that can emit LE**

   * Often means staying close to Watcom tooling, or writing your own LE “repacker” fed by object code + relocations.
2. **Recreate objects with original flags**

   * Code RX, data RW, bss zero-fill, etc.
3. **Emit correct fixups**

   * Especially selector fixups and far pointer fixups.
4. **Recreate entry table**

   * Same entry ordinal(s) if used.
5. **Preserve stub behavior**

   * Same MZ stub bytes if you can (some apps check them).

## Path 2: Rebuild to a different extender format but identical behavior

Easier *sometimes*, but risks subtle differences.

* You can still get “same behavior” for most apps, but anything relying on:

  * exact selectors,
  * exact object ordering,
  * self-checksumming,
  * page permissions,
    may break.

Since your ask is “exact same behavior”, Path 1 is the honest default.

---

# I) “Watcom-isms” you must preserve

These are common sources of “works except sometimes”.

1. **Structure packing and alignment**

   * Watcom defaults can differ from modern compilers.
   * Recreate padding bytes and field order exactly if data is serialized or hashed.
2. **FPU control word**

   * Some runtimes set precision/rounding; games sometimes depend on it.
3. **Signed overflow / flag behavior**

   * Old code sometimes relies on CPU flags after arithmetic; don’t “optimize” it away.
4. **Near/far pointer formats (if any 16-bit islands exist)**

   * Correct segment:offset layout, and how they’re stored in memory.

---

# J) Common DOS/4GW “integrity traps”

1. **Self-checksumming**

   * Code pages hashed at runtime → rebuilt bytes must match or patch out checks.
2. **Relocation-sensitive tables**

   * Pointer tables that must be fixed up exactly (size/stride matters).
3. **Self-modifying code**

   * Requires writable code pages or a copy-to-RW buffer that is executed.
4. **Uninitialized memory luck**

   * Original environment might produce zeros “by chance”; new build may not.

---

# K) Verification: DOSBox-X debugger checklist

1. **Break on program entry**

   * Confirm initial CS:EIP hits the same prologue path.
2. **Break on `int 31h` and log**

   * Compare sequence of DPMI calls vs original.
3. **Break on `int 21h` and log file ops**

   * Same open/read/seek patterns.
4. **Compare key memory snapshots**

   * After CRT init, after resource load, after first frame / first command loop.

---

# L) Minimal “done” criteria for behavior-identical

* Same exit code, same outputs, same visible behavior under the same emulator settings.
* Same input handling edge cases (keyboard timing is a common mismatch).
* Same file I/O patterns (especially if they do weird seek/write combos).
* No reliance on “undefined luck” (uninitialized reads) in your build.

---

## A very pragmatic final note

For DOS/4GW LE, the three dragons are:

* **selector-related fixups**,
* **object flags/alignment**,
* **self-integrity/self-modifying behavior**.

Nail those, and the rest is usually “just” a mountain of careful labeling and relocation hygiene.

Here’s a **“first ~2000 instructions” boot trace** you’ll commonly see in **DOS/4GW-style LE** programs, plus what each phase tells you about **selectors, objects, and layout**.

## Phase 0: Real-mode stub finds a path into protected mode

Typical behaviors (not always all of them):

1. **Check CPU / mode**

* Often via multiplex calls like **INT 2Fh** (“Get CPU mode”, “get switch entrypoint”, etc.).

2. **Obtain the real→protected mode switch entry**

* The classic one is **INT 2Fh AX=1687h** (Obtain Real-to-Protected Mode Switch Entry Point).
  **What it implies:** you’re going to see a *standard* DPMI-based protected-mode bring-up (not raw VCPI wizardry).

3. **Jump into the extender’s protected-mode entry**

* After this, the visible action shifts to **INT 31h** calls.

---

## Phase 1: Protected-mode bring-up (selectors and memory model appear)

This is where the program (or runtime/extender glue) constructs the world you must recreate.

### 1) Ask the DPMI host what it supports

* **INT 31h AX=0400h Get Version** 
* Often followed by **AX=0500h Get Free Memory Information**
  **Implies:** the program will choose strategies based on host quirks / available memory (so matching host matters for “exact behavior”).

### 2) Allocate selectors (LDT descriptors)

* **AX=0000h Allocate LDT Descriptors** 
**Implies about LE objects:**
* If you see **a few descriptors**, they’re probably setting up a **flat model** + maybe a couple helper selectors.
* If you see **many descriptors**, they may be creating **one selector per LE object** (or per arena/heap region).

### 3) Set descriptor base/limit/rights (this is the big tell)

* **AX=0007h Set Segment Base Address** 
* **AX=0008h Set Segment Limit** 
* **AX=0009h Set Descriptor Access Rights**

**What it implies (super useful heuristics):**

* **If base = 0 and limit ≈ 4GB** (often 0xFFFFF with granularity): they’re building a **flat selector**. That usually means:

  * pointers in code are treated like linear addresses,
  * LE object boundaries matter less *for addressing*, but still matter for **page permissions**, **integrity checks**, and **fault behavior**.
* **If base = (some linear address of an object) and limit = object_size-1**, repeated per object: they’re mapping **each LE object into its own selector**.

  * In this world, your rebuild must preserve **object order, sizes, and flags** much more strictly, because selectors are “semantic”.

### 4) Allocate big protected-mode memory blocks (heap / temp arenas)

* **AX=0501h Allocate Memory Block** 
* Sometimes later: **AX=0503h Resize Memory Block**
  **Implies:** the runtime is making a heap/arena whose **address** might leak into game logic (pointer comparisons, hash tables, “randomness”, etc.). For exact matching, you often need the **same DPMI host + similar allocation order**.

### 5) Allocate “DOS memory” (conventional, for real-mode interactions)

* **AX=0100h Allocate DOS Memory Block**
  **Implies:** the program likely does at least one of:
* real-mode interrupt simulation,
* VESA BIOS calls via real-mode,
* DMA/sound buffers that want low memory,
* DOS file APIs that prefer/require low buffers (some code is just conservative).

### 6) Set up interrupt/exception hooks (protected and/or real mode)

* Get/set protected-mode interrupt vectors:

  * **AX=0204h Get Protected Mode Interrupt Vector**
  * **AX=0205h Set Protected Mode Interrupt Vector**
* Get/set exception handler vectors:
* **AX=0202h / 0203h** 

**Implies:** you must be careful in your rebuild with:

* descriptor privileges/rights,
* stack selector correctness,
* whether the program chains old handlers (very common).

### 7) Real-mode calls and callbacks (if the program needs BIOS/DOS “the old way”)

* **AX=0300h Simulate Real Mode Interrupt**
* **AX=0303h Allocate Real Mode Callback Address**

**Implies:**

* There’s a boundary-crossing ABI (register packs, stack frames, selectors:offset pointers) you must preserve exactly.
* Games doing VESA BIOS calls through DPMI often show up here.

---

## Phase 2: C runtime initialization (Watcom/DOS/4GW flavor)

Once the world exists, you typically see:

1. **Set up stack / stack probes**

* Guard/probe patterns to ensure stack is committed/usable.

2. **Zero `.bss` and copy `.data`**

* This is where LE object boundaries can matter:

  * if `.bss` is a separate zero-fill object, you’ll see big clears.
  * if `.data` lives in one object and `.bss` in another, you’ll see two distinct regions.

3. **Initialize FPU**

* Often `fninit` + control word setup.

4. **Parse PSP / command line / environment**

* Even in protected mode, DOS-era CRTs still care deeply about PSP conventions.

**Implication for rebuilding:** this phase is where “minor” layout differences become visible as different pointer values, different alignment, different table addresses.

---

## Phase 3: Transition into the “real program”

You’ll usually see a clean handoff:

* runtime init → constructors (if any) → `main` / game loop
* first wave of I/O interrupts:

  * DOS file opens (`int 21h`)
  * VESA/VGA setup (`int 10h` either direct or via simulate-real-mode)
  * sound init (ports + maybe IRQ hooks)

---

# What to log (so you can separate glue from real logic fast)

If you’re tracing in DOSBox-X or similar, the “high signal” log is:

1. Every **INT 31h** call: record **AX**, and key in/out registers.
2. Pay special attention to:

   * 0000/0007/0008/0009 (descriptor construction)
   * 0501 (big allocations)
   * 0205 (interrupt hooks)
   * 0300/0303 (real-mode boundary crossings)
3. Correlate the **bases/limits** being set with your **LE object table**:

   * if you can match “descriptor base == object linear base”, you’ve basically solved the mapping.

---

## Quick pattern decoder (the “one glance” rules)

* **One flat selector created early** → program likely uses 32-bit linear addressing everywhere; objects still matter for permissions/checks.
* **Many selectors with different bases** → program is treating LE objects as real segments; your rebuild must preserve object topology very strictly.
* **Early 0100h + 0300h usage** → real-mode BIOS/DOS integration division; rebuild must preserve the register-pack ABI and buffer locations.
* **Interrupt vector hooks early** → be paranoid about stack selector and descriptor rights; tiny differences can become “random” crashes later.


Here’s a **concrete early-boot “timeline worksheet”** you can expect in a typical **DOS/4GW-ish LE** program, plus a **fill-in-the-blanks spec template** that turns your debugger log into a clean “this selector == this LE object/memory block” mapping.

## 1) The expected call sequence (with what to write down)

### A. Real mode: detect DPMI host + get the mode-switch entry

1. `int 2Fh, AX=1687h` → **get real→protected mode switch entry + host flags**
   Write down: returned flags (32-bit supported?), and whatever entry pointer/requirements you see used next. 

### B. Protected mode: “inventory the host”

2. `int 31h, AX=0400h` (**Get DPMI version**)
   Write down: major/minor + flags. 
3. Often `int 31h, AX=0500h` (**Get Free Memory Information**)
   Write down: buffer contents if you can (it’s advisory, but many runtimes branch on it). 

### C. Build selectors (this is the money)

4. `int 31h, AX=0003h` (**Get selector increment**)
   Write down: increment value (needed when descriptors are allocated in runs). 

5. `int 31h, AX=0000h` (**Allocate LDT descriptors**)
   Write down: `CX=requested count`, `AX=base selector returned`. 

6. For each selector they intend to use, you usually see a tight cluster:

* `int 31h, AX=0007h` (**Set segment base**)
* `int 31h, AX=0008h` (**Set segment limit**)
* `int 31h, AX=0009h` (**Set access rights/type**)

Write down (per selector):

* base (linear), limit, access rights,
* and which LE object / region that base smells like.

**Fast inference rule:**

* If you see **one selector** get base=0 and limit≈4GB → “flat model selector”.
* If you see **many selectors** get different bases/limits that match object sizes → “one selector per LE object/region”.

### D. Allocate memory blocks (and later map them with selectors)

7. `int 31h, AX=0501h` (**Allocate memory block**)
   Write down: requested size, returned linear base, returned handle (used later to resize/free).
   (Then watch for selectors being set to that returned base via 0007/0008/0009.)

8. `int 31h, AX=0100h` (**Allocate DOS low memory**)
   Write down: returned real-mode segment + returned protected-mode selector.

### E. Hook interrupts / exceptions (common in games, audio, timer, keyboard)

9. `int 31h, AX=0204h / 0205h` (**Get/Set protected-mode interrupt vector**)
   Write down: interrupt number (BL), old handler (for chaining), new handler address.

### F. Real-mode bridge (BIOS/VESA/DOS calls from protected mode)

10. `int 31h, AX=0303h` (**Allocate real-mode callback address**)
    Write down: callback real-mode seg:off and the protected-mode target routine.
11. `int 31h, AX=0300h` (**Simulate real-mode interrupt**)
    Write down: BL = interrupt number (often 10h/21h), and what buffers/pointers are involved. 

### G. CRT init → `main`

Then you’ll usually see `.bss` clears, `.data` copies, FPU init, command line parsing, etc. The key is: by now you should already have your selector/object mapping nailed.

---

## 2) A practical “log line format” (copy/paste into a text file)

Every time you hit an `int 31h`, record a single line like:

* `#123  INT31 AX=0000  IN: CX=0003  OUT: CF=0 AX=00A7  NOTE: alloc LDT (3 desc) baseSel=00A7`
* `#124  INT31 AX=0007  IN: BX=00A7 CX:DX=00F2:1000  OUT: CF=0  NOTE: setBase sel=00A7 base=0x00F21000`
* `#125  INT31 AX=0008  IN: BX=00A7 CX:DX=000F:FFFF  OUT: CF=0  NOTE: setLimit sel=00A7 lim=0x000FFFFF`
* `#126  INT31 AX=0009  IN: BX=00A7 CL=?? CH=??  OUT: CF=0  NOTE: rights sel=00A7 (code/data?)`
* `#150  INT31 AX=0501  IN: BX:CX=size  OUT: CF=0 BX:CX=linBase SI:DI=handle  NOTE: heap block`

The only goal: later you can sort/group by selector and memory handle.

---

## 3) The “spec template” you end up with (fill this from your log)

### Environment

* DPMI host: __________ (DOSBox-X internal / CWSDPMI / etc.)
* DPMI version/flags (0400h): __________
* Memory info consulted (0500h): yes/no; fields used: __________ 

### LE object map (from parsing the LE)

For each LE object N:

* size (virt/file), flags (RX/RW), file page ranges: __________

### Selector ledger (the core)

For each selector you see configured via 0007/0008/0009:

* Selector: ______
* Base (0007h): ______ 
* Limit (0008h): ______ 
* Rights (0009h): ______ 
* Backing region:

  * [ ] LE object #__
  * [ ] DPMI block handle __ (from 0501h)
  * [ ] DOS lowmem block (from 0100h)
* Notes (flat selector? stack? scratch?): ______

Also record:

* Selector increment (0003h): ______ 
* Descriptor allocations (0000h): list each (count → baseSel). 

### Memory blocks

* DPMI linear blocks (0501h):

  * handle SI:DI = __ → base = __ size = __ 
* DOS lowmem blocks (0100h):

  * real-mode seg = __, pm selector = **, size(paras)=**

### Interrupt hooks

* Protected-mode vectors set (0205h):

  * int __ old=(sel:off) __ new=(sel:off) __ chained? __ ()

### Real-mode bridge usage

* Callbacks allocated (0303h): list them and who calls them.
* Simulated interrupts (0300h): which int numbers, and which buffers/structures passed. 

---

## 4) What this buys you when rebuilding

Once that spec is filled, you can rebuild with confidence because you know:

* which selectors must exist,
* which bases/limits/rights must be reproduced,
* which LE objects correspond to which runtime segments,
* which real-mode shims (0300/0303) must remain ABI-identical.

