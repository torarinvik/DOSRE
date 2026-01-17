# BIN16 mnemonic promoter (C++)

This tool turns a **db-only** MASM/WASM-style dump into a **mnemonic-rich** version, while enforcing the invariant:

- the assembled+linked output must be **byte-identical** to the original binary

It uses two oracles:

- Fast oracle (default): assemble a *single* candidate instruction with `wasm`, disassemble the produced `.obj` with `wdis`, and compare the emitted bytes.
- Slow oracle (fallback): assemble + `wlink format raw bin` the full file and compare the rebuilt raw bytes.
It does this by repeatedly trying to replace `db ...` lines with the decoded mnemonic (from the end-of-line comment), assembling with OpenWatcom (`wasm`), linking a flat binary with `wlink format raw bin`, and keeping only the replacements that still compare equal.

## Build

- `make`

## Usage

- `./bin16_promote_wasm --in input.asm --orig original.bin --out promoted.asm`

Options:

- `--wasm PATH` / `--wdis PATH` / `--wlink PATH` (defaults: `wasm`/`wdis`/`wlink` from `PATH`)
- `--jobs N` run the fast per-instruction oracle with N worker threads (default: 1)
- `--chunk N` try to promote N lines at a time (default: 1024)
- `--wasm-warn-level N` pass `-w=N` to `wasm` (e.g. `0` silences warnings)
- `--quiet` reduce output (still prints periodic progress + final summary)
- `--keep-workdir` keep temp files if you want to inspect failures

Notes:

- Requires OpenWatcom tools on PATH (`wasm`, `wdis`, `wlink`).
- The input `.asm` is typically produced by `cport/bin16dump/bin16_dump_db --decode 1`.
 
