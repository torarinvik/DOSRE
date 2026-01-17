using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;
using DOSRE.Analysis;
using DOSRE.Dasm;
using DOSRE.Enums;
using DOSRE.Logging;
using DOSRE.Renderer.impl;
using NLog;

namespace DOSRE.UI.impl
{
    /// <summary>
    ///     ConsoleUI Class
    ///
    ///     This class is used when command line switches are passed into DOSRE, allowing users
    ///     to bypass the interactive UI functionality and work strictly with command line arguments
    /// </summary>
    public class ConsoleUI : IUserInterface
    {
        /// <summary>

    /// <summary>
    ///     Optional: cache the intermediate LE .asm (next to -O) and reuse it on subsequent runs.
    ///     Enabled with -LEDECOMPCACHEASM.
    /// </summary>
    private bool _bLeDecompCacheAsm;

        /// <summary>

    /// <summary>
    ///     Optional: decompile from an already generated .asm file (skips LE disassembly)
    /// </summary>
    private string _leDecompileAsmFile;

    /// <summary>
    ///     Optional: only emit a single function (func_XXXXXXXX or hex address)
    /// </summary>
    private string _leOnlyFunction;

    /// <summary>
    ///     Optional: export LE call graph in DOT format.
    ///     Specified with -LECALLGRAPHDOT <file.dot>
    /// </summary>
    private string _leCallGraphDot;

    /// <summary>
    ///     Optional: export LE call graph in JSON format.
    ///     Specified with -LECALLGRAPHJSON <file.json>
    /// </summary>
    private string _leCallGraphJson;

    /// <summary>
    ///     Optional: export LE per-function CFG in DOT format.
    ///     Specified with -LECFGDOT <file.dot>
    /// </summary>
    private string _leCfgDot;

    /// <summary>
    ///     Optional: export whole-program LE CFG index in DOT format (clusters per function).
    ///     Specified with -LECFGALLDOT <file.dot>
    /// </summary>
    private string _leCfgAllDot;

    /// <summary>
    ///     Optional: export whole-program LE CFG index in JSON format.
    ///     Specified with -LECFGALLJSON <file.json>
    /// </summary>
    private string _leCfgAllJson;

    /// <summary>
    ///     Optional: export a compact LE analysis report in JSON format.
    ///     Specified with -LEREPORTJSON <file.json>
    /// </summary>
    private string _leReportJson;

    /// <summary>
    ///     Optional: include per-function details in the -LEREPORTJSON payload.
    ///     Enabled with -LEREPORTFUNCS.
    /// </summary>
    private bool _bLeReportFuncs;

    /// <summary>
    ///     Optional: export a best-effort normalized LE fixup table in JSON format.
    ///     Specified with -LEFIXUPSJSON <file.json>
    /// </summary>
    private string _leFixupsJson;

    /// <summary>
    ///     Optional: export LE import map + best-effort "where referenced" xrefs in JSON format.
    ///     Specified with -LEIMPORTSJSON <file.json>
    /// </summary>
    private string _leImportsJson;

    /// <summary>
    ///     Optional: export reachability-based code marking (reachable code ranges vs data candidates).
    ///     Specified with -LEREACHJSON <file.json>
    /// </summary>
    private string _leReachJson;

    /// <summary>
    ///     Optional: import IDA .map symbol names and append as end-of-line hints (best-effort).
    ///     Specified with -LEIDAMAP <file.map>
    /// </summary>
    private string _leIdaMapFile;

    /// <summary>
    ///     Optional: import Binary Ninja IR text export and append as end-of-line hints (best-effort).
    ///     Specified with -LEBNIR <file.txt>
    /// </summary>
    private string _leBinaryNinjaIrFile;
        ///     Logger Implementation
        /// </summary>
        protected static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));

        /// <summary>
        ///     Args passed in via command line
        /// </summary>
        private readonly string[] _args;

        /// <summary>
        ///     Input File
        ///     Specified by the -i argument
        /// </summary>
        private string _sInputFile = string.Empty;

        /// <summary>
        ///     Output File
        ///     Specified with the -o argument
        /// </summary>
        private string _sOutputFile = string.Empty;

        /// <summary>
        ///     Minimal Disassembly
        ///     Specified with the -minimal argument
        ///     Will only do basic disassembly of opcodes
        /// </summary>
        private bool _bMinimal;

        /// <summary>
        ///     Additional analysis mode
        ///     Specified with the -analysis argument
        ///     Performs extra best-effort analysis passes (subroutines, loop patterns, optional import annotation).
        /// </summary>
        private bool _bAnalysis;

        /// <summary>
        ///     Strings Analysis
        ///     Specified with the -string argument
        ///     Includes all strings discovered in DATA segments at the end of the disassembly output
        /// </summary>
        private bool _bStrings;

        /// <summary>
        ///     Target DOS version for interrupt/service annotations
        ///     Specified with the -dosver <major.minor> argument
        ///     Example: -dosver 6.22
        /// </summary>
        private string _dosVersion = "6.22";

        /// <summary>
        ///     LE (DOS4GW) full disassembly
        ///     Specified with the -lefull argument
        ///     For LE inputs, disassembles executable objects from the start instead of starting at entry point.
        /// </summary>
        private bool _bLeFull;

        /// <summary>
        ///     LE (DOS4GW) byte limit
        ///     Specified with the -lebytes <n> argument
        ///     For LE inputs, limits disassembly output to N bytes from the chosen start offset.
        /// </summary>
        private int? _leBytesLimit;

        /// <summary>
        ///     LE render limit (max instructions per object)
        ///     Specified with the -lerenderlimit <n> argument
        ///     0 disables instruction rendering entirely (insights-only output).
        /// </summary>
        private int? _leRenderLimit;

        /// <summary>
        ///     LE insights parallelism (jobs)
        ///     Specified with the -lejobs <n> argument
        ///     Defaults to 1 (no parallelism).
        /// </summary>
        private int _leJobs = 1;

        /// <summary>
        ///     Optional LE linear start address override (hex). If set, disassembly starts at this address.
        ///     Specified with the -lestart <hex> argument
        /// </summary>
        private uint? _leStartLinear;

        /// <summary>
        ///     Output slicing (KB)
        ///     Specified with the -splitkb <n> argument
        ///     When used with -o, splits output into multiple numbered files about n KB each.
        /// </summary>
        private int? _splitKb;

        /// <summary>
        ///     LE decompilation chunk count (desired number of C chunk files)
        ///     Specified with the -lechunks <n> argument
        /// </summary>
        private int _leChunks = 0;

        /// <summary>
        ///     Macro de-duplication
        ///     Specified with the -macros argument
        ///     Post-processes output to collapse repeated straight-line instruction chunks into macros.
        /// </summary>
        private bool _bMacros;

        /// <summary>
        ///     LE (DOS4GW) fixup annotations
        ///     Specified with the -lefixups argument
        ///     For LE inputs, parses fixup records (best-effort) and annotates instructions when fixups apply.
        /// </summary>
        private bool _bLeFixups;

        /// <summary>
        ///     LE (DOS4GW) globals/symbolization
        ///     Specified with the -leglobals argument
        ///     For LE inputs, emits g_XXXXXXXX EQU 0xXXXXXXXX derived from disp32 fixups and rewrites operands.
        /// </summary>
        private bool _bLeGlobals;

        /// <summary>
        ///     LE (DOS4GW) insights mode
        ///     Specified with the -leinsights argument
        ///     For LE inputs, performs additional best-effort analysis (functions/CFG/xrefs/stack vars/strings).
        /// </summary>
        private bool _bLeInsights;

        /// <summary>
        ///     Export reconstructed LE object bytes.
        ///     Specified with -LEEXPORTOBJ <index> <file.bin>
        /// </summary>
        private int? _leExportObjIndex;
        private string _leExportObjFile;

        /// <summary>
        ///     LE (DOS4GW) decompile (pseudo-C)
        ///     Specified with the -ledecomp or -ledecompile argument
        ///     For LE inputs, emits best-effort pseudo-C derived from the LE disassembly output.
        /// </summary>
        private bool _bLeDecompile;

        /// <summary>
        ///     LE unwrap helper for MZ containers with BW overlay headers.
        ///     Specified with the -leunwrap argument.
        ///     Some games ship as an MZ stub with a BW overlay header that points at an embedded bound MZ+LE.
        ///     When enabled, DOSRE extracts the embedded bound EXE and runs the LE pipeline on that instead.
        /// </summary>
        private bool _bLeUnwrap;

        /// <summary>
        ///     LE header detection fallback for unusual MZ containers.
        ///     Specified with the -lescanmz argument.
        ///     When enabled, DOSRE will (as a last resort) scan the computed MZ overlay region for an LE header.
        /// </summary>
        private bool _bLeScanMz;

        /// <summary>
        ///     LE (DOS4GW) fixup dump
        ///     Specified with the -lefixdump [maxPages] argument
        ///     For LE inputs, emits a raw per-page fixup table dump to help reverse the record layout.
        /// </summary>
        private bool _bLeFixDump;

        /// <summary>
        ///     Optional page limit for -lefixdump
        /// </summary>
        private int? _leFixDumpMaxPages;

        /// <summary>
        ///     DOS MZ full disassembly
        ///     Specified with the -mzfull argument
        /// </summary>
        private bool _bMzFull;

        /// <summary>
        ///     DOS MZ byte limit
        ///     Specified with the -mzbytes <n> argument
        /// </summary>
        private int? _mzBytesLimit;

        /// <summary>
        ///     DOS MZ insights
        ///     Specified with the -mzinsights argument
        /// </summary>
        private bool _bMzInsights;

        /// <summary>
        ///     MZ byte-perfect reassembly export (NASM -f bin style)
        ///     Specified with -MZREASM <file.asm>
        /// </summary>
        private string _mzReasmAsm;

        /// <summary>
        ///     Optional JSON metadata export for -MZREASM
        ///     Specified with -MZREASMJSON <file.json>
        /// </summary>
        private string _mzReasmJson;

        /// <summary>
        ///     MZ byte-perfect reassembly export (OpenWatcom WASM/MASM compatible)
        ///     Specified with -MZREASMWASM <file.asm>
        /// </summary>
        private string _mzReasmAsmWasm;

        /// <summary>
        ///     Toolchain hint (best-effort heuristics)
        ///     Specified with -borland or -watcom
        /// </summary>
        private EnumToolchainHint _toolchainHint = EnumToolchainHint.None;

        /// <summary>
        ///     Flat 16-bit binary mode (COM-like / raw binary)
        ///     Specified with -BIN16
        /// </summary>
        private bool _bBin16;

        /// <summary>
        ///     Flat binary insights (best-effort string literal scanning + annotations)
        ///     Specified with -BININSIGHTS
        /// </summary>
        private bool _bBinInsights;

        /// <summary>
        ///     (DOS16) Looser INT-based heuristic renames (useful for quick mapping; may increase noise).
        ///     Specified with -BIN16LOOSEINT
        /// </summary>
        private bool _bBin16LooseInt;

        /// <summary>
        ///     (DOS16) Looser port-I/O heuristic renames (VGA/AdLib/etc). Useful for quick mapping; may increase noise.
        ///     Specified with -BIN16LOOSEIO
        /// </summary>
        private bool _bBin16LooseIo;

        /// <summary>
        ///     Emit inline string labels (str_XXXX:) at referenced string addresses.
        ///     Specified with -BINSTRLABELS
        /// </summary>
        private bool _bBinStrLabels;

        /// <summary>
        ///     Emit MASM/WASM-compatible assembly output for BIN16 (default).
        ///     Specified with -BINMASM / -BINWASM; disabled with -BINLISTING.
        /// </summary>
        private bool _bBinMasmCompat = true;

        /// <summary>
        ///     In BIN16 MASM/WASM mode, emit decoded instruction mnemonics instead of `db ... ; disasm` lines.
        ///     Specified with -BININSTR.
        /// </summary>
        private bool _bBinInstr;

        /// <summary>
        ///     In BIN16 MASM/WASM mode, emit mnemonics when they are likely to reassemble to identical bytes,
        ///     but fall back to `db ...` (with mnemonic comment) for known encoding-ambiguous cases.
        ///     Specified with -BININSTRSAFE.
        /// </summary>
        private bool _bBinInstrSafe;

        // Safe mnemonic fallback toggles (only relevant when -BININSTRSAFE is enabled).
        private bool _bBinInstrSafeJumps = true;
        private bool _bBinInstrSafeImm = true;
        private bool _bBinInstrSafeRegReg = true;
    private bool _bBinInstrSafeForceJumps = false;

        /// <summary>
        ///     In BIN16 MASM/WASM mode, keep output byte-perfect by always emitting `db ...`,
        ///     but include the decoded mnemonic as a comment for readability.
        ///     Specified with -BININSTRDB.
        /// </summary>
        private bool _bBinInstrDb;

        /// <summary>
        ///     Emit a best-effort code/data map as comments at the end of BIN16 output.
        ///     Specified with -BINMAP.
        /// </summary>
        private bool _bBinMap;

        /// <summary>
        ///     Flat binary origin (base address)
        ///     Specified with -BINORG <hex>
        /// </summary>
        private uint _binOrigin = 0x100;

        /// <summary>
        ///     Flat binary bytes limit
        ///     Specified with -BINBYTES <n>
        /// </summary>
        private int? _binBytesLimit;

        /// <summary>
        ///     BIN16 byte-perfect reassembly export (NASM -f bin style)
        ///     Specified with -BINREASM <file.asm>
        /// </summary>
        private string _binReasmAsm;

        /// <summary>
        ///     BIN16 byte-perfect reassembly export (OpenWatcom WASM/MASM compatible)
        ///     Specified with -BINREASMWASM <file.asm>
        /// </summary>
        private string _binReasmAsmWasm;

        /// <summary>
        ///     Optional JSON metadata export for -BINREASM
        ///     Specified with -BINREASMJSON <file.json>
        /// </summary>
        private string _binReasmJson;

        /// <summary>
        ///     Lift a promoted BIN16/WASM assembly listing (byte-authoritative comments) into a crude AST.
        ///     Specified with -BINLIFTASM <file.asm>
        /// </summary>
        private string _binLiftAsm;

        /// <summary>
        ///     Output JSON for -BINLIFTASM
        ///     Specified with -BINLIFTJSON <file.json>
        /// </summary>
        private string _binLiftJson;

        /// <summary>
        ///     Output C header for -BINLIFTASM
        ///     Specified with -BINLIFTH <file.h>
        /// </summary>
        private string _binLiftH;

        /// <summary>
        ///     Output C file for -BINLIFTASM
        ///     Specified with -BINLIFTC <file.c>
        /// </summary>
        private string _binLiftC;

        /// <summary>
        ///     Lift a promoted BIN16/WASM assembly listing (byte-authoritative comments) into MC0 (Machine-C Level 0).
        ///     Specified with -BINMC0ASM <file.asm>
        /// </summary>
        private string _binMc0Asm;

        /// <summary>
        ///     Output MC0 text for -BINMC0ASM
        ///     Specified with -BINMC0OUT <file.mc0>
        /// </summary>
        private string _binMc0Out;

        /// <summary>
        ///     Output MC0 JSON for -BINMC0ASM
        ///     Specified with -BINMC0JSON <file.json>
        /// </summary>
        private string _binMc0Json;

        /// <summary>
        ///     Output byte-faithful re-emitted assembly listing (db ...) from MC0.
        ///     Specified with -BINMC0REASM <file.asm>
        /// </summary>
        private string _binMc0Reasm;

        /// <summary>
        ///     Verify MC0 pipeline rebuilds an original flat binary: promoted asm -> MC0 -> reasm -> wasm+wlink -> byte-compare.
        ///     Specified with -BINMC0VERIFYASM <file.promoted.asm>
        /// </summary>
        private string _binMc0VerifyAsm;

        /// <summary>
        ///     Original binary to compare against for -BINMC0VERIFYASM.
        ///     Specified with -BINMC0VERIFYORIG <file.exe>
        /// </summary>
        private string _binMc0VerifyOrig;

        /// <summary>
        ///     Output directory for verifier intermediates/results.
        ///     Specified with -BINMC0VERIFYOUTDIR <dir>
        /// </summary>
        private string _binMc0VerifyOutDir;

        /// <summary>
        ///     Override path to OpenWatcom wasm.
        ///     Specified with -BINMC0WASM <path>
        /// </summary>
        private string _binMc0WasmPath;

        /// <summary>
        ///     Override path to OpenWatcom wlink.
        ///     Specified with -BINMC0WLINK <path>
        /// </summary>
        private string _binMc0WlinkPath;

        /// <summary>
        ///     MC1 input file (deterministic sugar layer over MC0).
        ///     Specified with -BINMC1IN <file.mc1>
        /// </summary>
        private string _binMc1In;

        /// <summary>
        ///     Lift a promoted asm listing into MC1 (promoted asm -> MC0 -> MC1).
        ///     Specified with -BINMC1LIFTASM <file.promoted.asm>
        /// </summary>
        private string _binMc1LiftAsm;

        /// <summary>
        ///     Output MC1 text for -BINMC1LIFTASM
        ///     Specified with -BINMC1LIFTOUT <file.mc1>
        /// </summary>
        private string _binMc1LiftOut;

        /// <summary>
        ///     MC0 output file from desugaring MC1.
        ///     Specified with -BINMC1OUT <file.mc0>
        /// </summary>
        private string _binMc1Out;

        /// <summary>
        ///     Optional: expected MC0 file to compare against (byte/origin identity).
        ///     Specified with -BINMC1EXPECT <file.mc0>
        /// </summary>
        private string _binMc1Expect;

        /// <summary>
        ///     Prove MC1 lowers to the exact same MC0 origin stream as a promoted asm, and optionally prove the rebuilt exe is byte-equal.
        ///     Specified with -BINMC1PROVEIN <file.mc1>
        /// </summary>
        private string _binMc1ProveIn;

        /// <summary>
        ///     Promoted asm used as MC0 baseline for -BINMC1PROVEIN.
        ///     Specified with -BINMC1PROVEASM <file.promoted.asm>
        /// </summary>
        private string _binMc1ProveAsm;

        /// <summary>
        ///     Original exe used for MC0 rebuild byte-compare in -BINMC1PROVEIN.
        ///     Specified with -BINMC1PROVEORIG <file.exe>
        /// </summary>
        private string _binMc1ProveOrig;

        /// <summary>
        ///     Output directory for chain proof intermediates.
        ///     Specified with -BINMC1PROVEOUTDIR <dir>
        /// </summary>
        private string _binMc1ProveOutDir;

        /// <summary>
        ///     Trace a window of lifted BIN16 bytes using Unicorn (host emulator).
        ///     Specified with -BINTRACEASM <file.asm>
        /// </summary>
        private string _binTraceAsm;

        /// <summary>
        ///     Output trace file for -BINTRACEASM
        ///     Specified with -BINTRACEOUT <file.txt>
        /// </summary>
        private string _binTraceOut;

        /// <summary>
        ///     Logical start address (hex) in the same address space as the byte-authoritative comments.
        ///     Specified with -BINTRACESTART <hex>
        /// </summary>
        private uint? _binTraceStart;

        /// <summary>
        ///     Trace window size (hex, max 0x10000)
        ///     Specified with -BINTRACEWINDOW <hex>
        /// </summary>
        private uint _binTraceWindow = 0x10000;

        /// <summary>
        ///     Max instruction steps to execute
        ///     Specified with -BINTRACESTEPS <n>
        /// </summary>
        private int _binTraceSteps = 10_000;

        /// <summary>
        ///     Debug: probe Unicorn P/Invoke load and uc_open/uc_close.
        ///     Enabled with -UNICORNPROBE
        /// </summary>
        private bool _bUnicornProbe;

        /// <summary>
        ///     Batch BIN16 reassembly export input directory
        ///     Specified with -BINDIRREASM <inDir> <outDir>
        /// </summary>
        private string _binDirReasmInDir;

        /// <summary>
        ///     Batch BIN16 reassembly export output directory
        ///     Specified with -BINDIRREASM <inDir> <outDir>
        /// </summary>
        private string _binDirReasmOutDir;

        /// <summary>
        ///     Batch BIN16 reassembly export output directory (OpenWatcom WASM/MASM compatible)
        ///     Specified with -BINDIRREASMWASM <inDir> <outDir>
        /// </summary>
        private string _binDirReasmOutDirWasm;

        /// <summary>
        ///     Optional extension filter for -BINDIRREASM (example: .ovl)
        ///     Specified with -BINDIREXT <ext>
        /// </summary>
        private string _binDirReasmExt;

        /// <summary>
        ///     Default Constructor
        /// </summary>
        /// <param name="args">string - Command Line Arguments</param>
        public ConsoleUI(string[] args)
        {
            _args = args;
        }

        /// <summary>
        ///     (IUserInterface) Runs the specified User Interface
        /// </summary>
        public void Run()
        {
            try
            {
                //Command Line Values

                static string NormalizeOpt(string arg)
                {
                    if (string.IsNullOrWhiteSpace(arg))
                        return string.Empty;

                    var a = arg.Trim();

                    // Support common switch prefixes: -foo, --foo, /foo
                    while (a.Length > 0 && (a[0] == '-' || a[0] == '/'))
                        a = a.Substring(1);

                    // Normalize separators: le-insights, le_insights => LEINSIGHTS
                    a = a.Replace("-", string.Empty).Replace("_", string.Empty);

                    return a.ToUpperInvariant();
                }

                for (var i = 0; i < _args.Length; i++)
                {
                    var opt = NormalizeOpt(_args[i]);
                    switch (opt)
                    {
                        case "LE":
                            // Convenience: allow `-LE <file>` as an alias for `-I <file>`.
                            // Users often read this as "LE input".
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LE requires a <file>");
                            _sInputFile = _args[i + 1];
                            i++;
                            break;
                        case "I":
                            if (i + 1 >= _args.Length) throw new Exception("Error: -I requires a <file>");
                            _sInputFile = _args[i + 1];
                            i++;
                            break;
                        case "O":
                            if (i + 1 >= _args.Length) throw new Exception("Error: -O requires a <file>");
                            _sOutputFile = _args[i + 1];
                            i++;
                            break;
                        case "MINIMAL":
                            _bMinimal = true;
                            break;
                        case "ANALYSIS":
                            _bAnalysis = true;
                            break;
                        case "STRINGS":
                            _bStrings = true;
                            break;
                        case "DOSVER":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -DOSVER requires a value (example: 6.22)");
                            _dosVersion = _args[i + 1];
                            i++;
                            break;
                        case "BIN16":
                            _bBin16 = true;
                            // Convenience: allow `-BIN16 <file>` as an alias for `-I <file> -BIN16`.
                            // Only consume the next arg if it does not look like another switch.
                            if (string.IsNullOrWhiteSpace(_sInputFile) && i + 1 < _args.Length)
                            {
                                var next = _args[i + 1];
                                if (!string.IsNullOrWhiteSpace(next) && next.Length > 0 &&
                                    (File.Exists(next) || (next[0] != '-' && next[0] != '/')))
                                {
                                    _sInputFile = next;
                                    i++;
                                }
                            }
                            break;
                        case "BININSIGHTS":
                            _bBinInsights = true;
                            break;
                        case "BIN16LOOSEINT":
                            _bBin16LooseInt = true;
                            break;
                        case "BIN16LOOSEIO":
                            _bBin16LooseIo = true;
                            break;
                        case "BINSTRLABELS":
                            _bBinStrLabels = true;
                            break;
                        case "BINMASM":
                        case "BINWASM":
                            _bBinMasmCompat = true;
                            break;
                        case "BININSTR":
                            _bBinInstr = true;
                            break;
                        case "BININSTRSAFE":
                            // Prefer mnemonic output, but keep rebuilds byte-identical by falling back to db
                            // for known ambiguous encodings (e.g., reg-reg ALU direction, imm width choices).
                            _bBinInstrSafe = true;
                            _bBinInstr = true;
                            _bBinInstrDb = false;
                            break;
                        case "BININSTRSAFEJUMPS":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BININSTRSAFEJUMPS requires 0 or 1");
                            _bBinInstrSafeJumps = _args[i + 1].Trim() switch
                            {
                                "0" => false,
                                "1" => true,
                                _ => throw new Exception("Error: -BININSTRSAFEJUMPS requires 0 or 1"),
                            };
                            i++;
                            break;

                        case "BININSTRSAFEJUMPSFORCE":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BININSTRSAFEJUMPSFORCE requires 0 or 1");

                            _bBinInstrSafeForceJumps = _args[i + 1].Trim() switch
                            {
                                "0" => false,
                                "1" => true,
                                _ => throw new Exception("Error: -BININSTRSAFEJUMPSFORCE requires 0 or 1"),
                            };
                            i++;
                            break;
                        case "BININSTRSAFEIMM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BININSTRSAFEIMM requires 0 or 1");
                            _bBinInstrSafeImm = _args[i + 1].Trim() switch
                            {
                                "0" => false,
                                "1" => true,
                                _ => throw new Exception("Error: -BININSTRSAFEIMM requires 0 or 1"),
                            };
                            i++;
                            break;
                        case "BININSTRSAFEREGREG":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BININSTRSAFEREGREG requires 0 or 1");
                            _bBinInstrSafeRegReg = _args[i + 1].Trim() switch
                            {
                                "0" => false,
                                "1" => true,
                                _ => throw new Exception("Error: -BININSTRSAFEREGREG requires 0 or 1"),
                            };
                            i++;
                            break;
                        case "BININSTRDB":
                            // Byte-perfect mnemonic mode: keep bytes as db but include mnemonics in comments.
                            // If both are set, prefer byte-perfect mode.
                            _bBinInstrDb = true;
                            _bBinInstr = false;
                            _bBinInstrSafe = false;
                            break;
                        case "BINMAP":
                            _bBinMap = true;
                            break;
                        case "BINLISTING":
                            _bBinMasmCompat = false;
                            break;
                        case "BINORG":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINORG requires a value (hex, e.g. 100 or 0x100)");
                            {
                                var sOrg = _args[i + 1].Trim();
                                if (sOrg.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    sOrg = sOrg.Substring(2);
                                if (!uint.TryParse(sOrg, System.Globalization.NumberStyles.HexNumber, null, out var org))
                                    throw new Exception("Error: -BINORG must be a hex number (e.g. 100 or 0x100)");
                                _binOrigin = org;
                            }
                            i++;
                            break;
                        case "BINBYTES":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINBYTES requires a value");
                            if (!int.TryParse(_args[i + 1], out var binBytesLimit) || binBytesLimit <= 0)
                                throw new Exception("Error: -BINBYTES must be a positive integer");
                            _binBytesLimit = binBytesLimit;
                            i++;
                            break;
                        case "BINREASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINREASM requires a <file.asm>");
                            _binReasmAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINREASMWASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINREASMWASM requires a <file.asm>");
                            _binReasmAsmWasm = _args[i + 1];
                            i++;
                            break;
                        case "BINREASMJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINREASMJSON requires a <file.json>");
                            _binReasmJson = _args[i + 1];
                            i++;
                            break;

                        case "BINLIFTASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINLIFTASM requires a <file.asm>");
                            _binLiftAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINLIFTJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINLIFTJSON requires a <file.json>");
                            _binLiftJson = _args[i + 1];
                            i++;
                            break;
                        case "BINLIFTH":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINLIFTH requires a <file.h>");
                            _binLiftH = _args[i + 1];
                            i++;
                            break;
                        case "BINLIFTC":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINLIFTC requires a <file.c>");
                            _binLiftC = _args[i + 1];
                            i++;
                            break;

                        case "BINMC0ASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0ASM requires a <file.asm>");
                            _binMc0Asm = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0OUT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0OUT requires a <file.mc0>");
                            _binMc0Out = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0JSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0JSON requires a <file.json>");
                            _binMc0Json = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0REASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0REASM requires a <file.asm>");
                            _binMc0Reasm = _args[i + 1];
                            i++;
                            break;

                        case "BINMC0VERIFYASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0VERIFYASM requires a <file.promoted.asm>");
                            _binMc0VerifyAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0VERIFYORIG":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0VERIFYORIG requires a <file.exe>");
                            _binMc0VerifyOrig = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0VERIFYOUTDIR":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0VERIFYOUTDIR requires a <dir>");
                            _binMc0VerifyOutDir = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0WASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0WASM requires a <path>");
                            _binMc0WasmPath = _args[i + 1];
                            i++;
                            break;
                        case "BINMC0WLINK":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC0WLINK requires a <path>");
                            _binMc0WlinkPath = _args[i + 1];
                            i++;
                            break;

                        case "BINMC1IN":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1IN requires a <file.mc1>");
                            _binMc1In = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1LIFTASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1LIFTASM requires a <file.promoted.asm>");
                            _binMc1LiftAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1OUT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1OUT requires a <file.mc0>");
                            _binMc1Out = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1LIFTOUT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1LIFTOUT requires a <file.mc1>");
                            _binMc1LiftOut = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1EXPECT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1EXPECT requires a <file.mc0>");
                            _binMc1Expect = _args[i + 1];
                            i++;
                            break;

                        case "BINMC1PROVEIN":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1PROVEIN requires a <file.mc1>");
                            _binMc1ProveIn = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1PROVEASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1PROVEASM requires a <file.promoted.asm>");
                            _binMc1ProveAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1PROVEORIG":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1PROVEORIG requires a <file.exe>");
                            _binMc1ProveOrig = _args[i + 1];
                            i++;
                            break;
                        case "BINMC1PROVEOUTDIR":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINMC1PROVEOUTDIR requires a <dir>");
                            _binMc1ProveOutDir = _args[i + 1];
                            i++;
                            break;

                        case "BINTRACEASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINTRACEASM requires a <file.asm>");
                            _binTraceAsm = _args[i + 1];
                            i++;
                            break;
                        case "BINTRACEOUT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINTRACEOUT requires a <file.txt>");
                            _binTraceOut = _args[i + 1];
                            i++;
                            break;
                        case "BINTRACESTART":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINTRACESTART requires a value (hex)");
                            {
                                var sHex = _args[i + 1].Trim();
                                if (sHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    sHex = sHex.Substring(2);
                                if (!uint.TryParse(sHex, System.Globalization.NumberStyles.HexNumber, null, out var v))
                                    throw new Exception("Error: -BINTRACESTART must be a hex number (e.g. 1A4 or 0x1A4)");
                                _binTraceStart = v;
                            }
                            i++;
                            break;
                        case "BINTRACEWINDOW":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINTRACEWINDOW requires a value (hex)");
                            {
                                var sWin = _args[i + 1].Trim();
                                if (sWin.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    sWin = sWin.Substring(2);
                                if (!uint.TryParse(sWin, System.Globalization.NumberStyles.HexNumber, null, out var v) || v == 0 || v > 0x10000)
                                    throw new Exception("Error: -BINTRACEWINDOW must be hex in range 1..0x10000");
                                _binTraceWindow = v;
                            }
                            i++;
                            break;
                        case "BINTRACESTEPS":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINTRACESTEPS requires a value");
                            if (!int.TryParse(_args[i + 1], out var steps) || steps <= 0)
                                throw new Exception("Error: -BINTRACESTEPS must be a positive integer");
                            _binTraceSteps = steps;
                            i++;
                            break;

                        case "UNICORNPROBE":
                            _bUnicornProbe = true;
                            break;
                        case "BINDIRREASM":
                            if (i + 2 >= _args.Length)
                                throw new Exception("Error: -BINDIRREASM requires <inDir> <outDir>");
                            _binDirReasmInDir = _args[i + 1];
                            _binDirReasmOutDir = _args[i + 2];
                            i += 2;
                            break;
                        case "BINDIRREASMWASM":
                            if (i + 2 >= _args.Length)
                                throw new Exception("Error: -BINDIRREASMWASM requires <inDir> <outDir>");
                            _binDirReasmInDir = _args[i + 1];
                            _binDirReasmOutDirWasm = _args[i + 2];
                            i += 2;
                            break;
                        case "BINDIREXT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -BINDIREXT requires an extension (example: .ovl)");
                            _binDirReasmExt = _args[i + 1];
                            i++;
                            break;
                        case "LEFULL":
                            _bLeFull = true;
                            break;
                        case "LEBYTES":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEBYTES requires a value");
                            if (!int.TryParse(_args[i + 1], out var bytesLimit) || bytesLimit <= 0)
                                throw new Exception("Error: -LEBYTES must be a positive integer");
                            _leBytesLimit = bytesLimit;
                            i++;
                            break;
                        case "LEFIXUPS":
                            _bLeFixups = true;
                            break;
                        case "LEGLOBALS":
                            _bLeGlobals = true;
                            break;
                        case "LEINSIGHTS":
                            _bLeInsights = true;
                            break;
                        case "LEIDAMAP":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEIDAMAP requires a <file.map>");
                            _leIdaMapFile = _args[i + 1];
                            i++;
                            break;
                        case "LEBNIR":
                        case "LEBINARYNINJAIR":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEBNIR requires a <file.txt>");
                            _leBinaryNinjaIrFile = _args[i + 1];
                            i++;
                            break;
                        case "LEEXPORTOBJ":
                            if (i + 2 >= _args.Length)
                                throw new Exception("Error: -LEEXPORTOBJ requires <index> <file.bin>");
                            if (!int.TryParse(_args[i + 1], out var objIdx) || objIdx <= 0)
                                throw new Exception("Error: -LEEXPORTOBJ <index> must be a positive integer");
                            _leExportObjIndex = objIdx;
                            _leExportObjFile = _args[i + 2];
                            i += 2;
                            break;
                        case "LERENDERLIMIT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LERENDERLIMIT requires a value");
                            if (!int.TryParse(_args[i + 1], out var renderLimit) || renderLimit < 0)
                                throw new Exception("Error: -LERENDERLIMIT must be a non-negative integer (0 = no render)");
                            _leRenderLimit = renderLimit;
                            i++;
                            break;
                        case "LEJOBS":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEJOBS requires a value");
                            if (!int.TryParse(_args[i + 1], out var jobs) || jobs <= 0)
                                throw new Exception("Error: -LEJOBS must be a positive integer");
                            _leJobs = jobs;
                            i++;
                            break;
                        case "LESTART":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LESTART requires a value (hex, e.g. A5BE2 or 0xA5BE2)");
                            var s = _args[i + 1].Trim();
                            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                s = s.Substring(2);
                            if (!uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var lin))
                                throw new Exception("Error: -LESTART must be a hex number (e.g. A5BE2 or 0xA5BE2)");
                            _leStartLinear = lin;
                            i++;
                            break;
                        case "LEDECOMP":
                        case "LEDECOMPILE":
                            _bLeDecompile = true;
                            break;
                        case "LEDECOMPASM":
                        case "LEDECOMPILEASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEDECOMPASM requires a <file.asm>");
                            _bLeDecompile = true;
                            _leDecompileAsmFile = _args[i + 1];
                            i++;
                            break;
                        case "LEDECOMPCACHEASM":
                            _bLeDecompile = true;
                            _bLeDecompCacheAsm = true;
                            break;
                        case "LEUNWRAP":
                            _bLeUnwrap = true;
                            break;
						case "LESCANMZ":
							_bLeScanMz = true;
							break;
                        case "LEFUNC":
                        case "LEONLYFUNC":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEFUNC requires a function label or hex address");
                            _leOnlyFunction = _args[i + 1];
                            i++;
                            break;
                        case "LEFIXDUMP":
                            _bLeFixDump = true;
                            if (i + 1 < _args.Length && int.TryParse(_args[i + 1], out var maxPages) && maxPages > 0)
                            {
                                _leFixDumpMaxPages = maxPages;
                                i++;
                            }
                            break;
                        case "LECALLGRAPHDOT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECALLGRAPHDOT requires a <file.dot>");
                            _leCallGraphDot = _args[i + 1];
                            i++;
                            break;
                        case "LECALLGRAPHJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECALLGRAPHJSON requires a <file.json>");
                            _leCallGraphJson = _args[i + 1];
                            i++;
                            break;
                        case "LECFGDOT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECFGDOT requires a <file.dot>");
                            _leCfgDot = _args[i + 1];
                            i++;
                            break;
                        case "LECFGALLDOT":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECFGALLDOT requires a <file.dot>");
                            _leCfgAllDot = _args[i + 1];
                            i++;
                            break;
                        case "LECFGALLJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECFGALLJSON requires a <file.json>");
                            _leCfgAllJson = _args[i + 1];
                            i++;
                            break;
                        case "LEREPORTJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEREPORTJSON requires a <file.json>");
                            _leReportJson = _args[i + 1];
                            i++;
                            break;
                        case "LEREPORTFUNCS":
                            _bLeReportFuncs = true;
                            break;
                        case "LEFIXUPSJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEFIXUPSJSON requires a <file.json>");
                            _leFixupsJson = _args[i + 1];
                            i++;
                            break;
                        case "LEIMPORTSJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEIMPORTSJSON requires a <file.json>");
                            _leImportsJson = _args[i + 1];
                            i++;
                            break;
                        case "LEREACHJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEREACHJSON requires a <file.json>");
                            _leReachJson = _args[i + 1];
                            i++;
                            break;
                        case "MZFULL":
                            _bMzFull = true;
                            break;
                        case "MZBYTES":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -MZBYTES requires a value");
                            if (!int.TryParse(_args[i + 1], out var mzBytesLimit) || mzBytesLimit <= 0)
                                throw new Exception("Error: -MZBYTES must be a positive integer");
                            _mzBytesLimit = mzBytesLimit;
                            i++;
                            break;
                        case "MZINSIGHTS":
                            _bMzInsights = true;
                            break;
                        case "MZREASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -MZREASM requires a <file.asm>");
                            _mzReasmAsm = _args[i + 1];
                            i++;
                            break;
                        case "MZREASMWASM":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -MZREASMWASM requires a <file.asm>");
                            _mzReasmAsmWasm = _args[i + 1];
                            i++;
                            break;
                        case "MZREASMJSON":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -MZREASMJSON requires a <file.json>");
                            _mzReasmJson = _args[i + 1];
                            i++;
                            break;
                        case "BORLAND":
                            if (_toolchainHint != EnumToolchainHint.None && _toolchainHint != EnumToolchainHint.Borland)
                                throw new Exception("Error: -BORLAND and -WATCOM are mutually exclusive");
                            _toolchainHint = EnumToolchainHint.Borland;
                            break;
                        case "WATCOM":
                            if (_toolchainHint != EnumToolchainHint.None && _toolchainHint != EnumToolchainHint.Watcom)
                                throw new Exception("Error: -BORLAND and -WATCOM are mutually exclusive");
                            _toolchainHint = EnumToolchainHint.Watcom;
                            break;
                        case "INTSKELETON":
                            // Generate an editable JSON skeleton from dosre.unknown-ints.txt.
                            // Usage:
                            //   -intskeleton <out.json>
                            //   -intskeleton <in.txt> <out.json>
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -INTSKELETON requires <out.json> or <in.txt> <out.json>");

                            var a1 = _args[i + 1];
                            var a2 = (i + 2 < _args.Length) ? _args[i + 2] : null;

                            string inPath;
                            string outPath;
                            if (!string.IsNullOrEmpty(a2) && !a2.StartsWith("-", StringComparison.Ordinal))
                            {
                                inPath = a1;
                                outPath = a2;
                                i += 2;
                            }
                            else
                            {
                                inPath = "dosre.unknown-ints.txt";
                                outPath = a1;
                                i += 1;
                            }

                            UnknownInterruptSkeletonGenerator.Generate(inPath, outPath);
                            _logger.Info($"Wrote interrupt skeleton to {outPath}");
                            return;
                        case "SPLITKB":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -SPLITKB requires a value");
                            if (!int.TryParse(_args[i + 1], out var splitKb) || splitKb <= 0)
                                throw new Exception("Error: -SPLITKB must be a positive integer");
                            _splitKb = splitKb;
                            i++;
                            break;
                        case "LECHUNKS":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LECHUNKS requires a value");
                            if (!int.TryParse(_args[i + 1], out var leChunks) || leChunks <= 0)
                                throw new Exception("Error: -LECHUNKS must be a positive integer");
                            _leChunks = leChunks;
                            i++;
                            break;
                        case "MACROS":
                            _bMacros = true;
                            break;
                        case "?":
                        case "H":
                        case "HELP":
                            Console.WriteLine("-LE <file> -- Input File (alias for -I; commonly used for LE/DOS4GW EXEs)");
                            Console.WriteLine("-I <file> -- Input File to DisassembleSegment");
                            Console.WriteLine("-O <file> -- Output File for Disassembly (Default ConsoleUI)");
                            Console.WriteLine("-BIN16 [file] -- Treat input as a flat 16-bit binary (COM-like / raw blob; no MZ/NE/LE header). Use -I <file> or pass [file] here.");
                            Console.WriteLine("-BINORG <hex> -- (with -BIN16) Base address/origin for the disassembly (default 0x100)");
                            Console.WriteLine("-BINBYTES <n> -- (with -BIN16) Limit disassembly to n bytes from start of file");
                            Console.WriteLine("-BININSIGHTS -- (with -BIN16) Best-effort string literal scan + inline string annotations");
                            Console.WriteLine("-BIN16LOOSEINT -- (with -BIN16) Looser INT-based heuristic renames (useful for quick mapping; may increase noise)");
                            Console.WriteLine("-BIN16LOOSEIO -- (with -BIN16) Looser port-I/O heuristic renames (VGA/AdLib/etc; may increase noise)");
                            Console.WriteLine("-BINSTRLABELS -- (with -BIN16/-BININSIGHTS) Emit inline str_XXXX: labels at referenced string addresses");
                            Console.WriteLine("-BINMASM / -BINWASM -- (with -BIN16) Emit MASM/WASM-compatible assembly source (default)");
                            Console.WriteLine("-BININSTR -- (with -BIN16 and -BINMASM/-BINWASM) Emit decoded instruction mnemonics instead of db-lines (best-effort)");
                            Console.WriteLine("-BININSTRSAFE -- (with -BIN16 and -BINMASM/-BINWASM) Emit mnemonics when safe, but fall back to db for encoding-ambiguous cases (mostly-mnemonic + byte-identical rebuild)");
                            Console.WriteLine("  -BININSTRSAFEJUMPS 0|1 -- (with -BININSTRSAFE) Control short-vs-near branch/jump fallback (default 1)");
                            Console.WriteLine("  -BININSTRSAFEIMM 0|1 -- (with -BININSTRSAFE) Control immediate-width fallback (add/sub/cmp imm, push imm, imul imm) (default 1)");
                            Console.WriteLine("  -BININSTRSAFEREGREG 0|1 -- (with -BININSTRSAFE) Control reg-reg encoding fallback (ALU dir + xchg ax,reg) (default 1)");
                            Console.WriteLine("  -BININSTRSAFEJUMPSFORCE 0|1 -- (with -BININSTRSAFE) Force short/near in jump mnemonics to keep byte-perfect output while maximizing mnemonics (default 0)");
                            Console.WriteLine("-BININSTRDB -- (with -BIN16 and -BINMASM/-BINWASM) Emit byte-perfect db-lines, with decoded mnemonics as comments (assemblable + readable)");
                            Console.WriteLine("-BINMAP -- (with -BIN16) Append a best-effort code/data map (ranges + reasons) as comments");
                            Console.WriteLine("-BINLISTING -- (with -BIN16) Emit analysis listing format (NOT assembler-ready)");
                            Console.WriteLine("-BINREASM <file.asm> -- (with -BIN16) Export byte-perfect NASM -f bin reconstruction (db), using -BINORG for the org directive");
                            Console.WriteLine("-BINREASMJSON <file.json> -- (with -BIN16) Export BIN16 metadata (origin + size) for the -BINREASM output");
                            Console.WriteLine("-BINREASMWASM <file.asm> -- (with -BIN16) Export byte-perfect reassembly in OpenWatcom WASM/MASM-compatible syntax (db + 8086 directives)");
                            Console.WriteLine("-BINLIFTASM <file.asm> -- Lift promoted BIN16/WASM asm (byte-authoritative comments) into a 1:1 crude AST");
                            Console.WriteLine("-BINLIFTJSON <file.json> -- (with -BINLIFTASM) Write the crude AST as JSON");
                            Console.WriteLine("-BINLIFTH <file.h> -- (with -BINLIFTASM) Write a C header for the lifted program table");
                            Console.WriteLine("-BINLIFTC <file.c> -- (with -BINLIFTASM) Write a compilable C file containing addr+bytes+asm text");
                            Console.WriteLine("-BINMC0ASM <file.asm> -- Lift promoted BIN16/WASM asm into MC0 (deterministic Machine-C w/ origin bytes)");
                            Console.WriteLine("-BINMC0OUT <file.mc0> -- (with -BINMC0ASM) Write MC0 text (deterministic; includes origin tags)");
                            Console.WriteLine("-BINMC0JSON <file.json> -- (with -BINMC0ASM) Write MC0 as JSON");
                            Console.WriteLine("-BINMC0REASM <file.asm> -- (with -BINMC0ASM) Write byte-faithful re-emitted asm listing (db ... per stmt)");
                            Console.WriteLine("-BINMC0VERIFYASM <file.promoted.asm> -- Verify: promoted asm -> MC0 -> reasm -> wasm+wlink -> byte-compare");
                            Console.WriteLine("-BINMC0VERIFYORIG <file.exe> -- (with -BINMC0VERIFYASM) Original binary to compare against");
                            Console.WriteLine("-BINMC0VERIFYOUTDIR <dir> -- (optional) Where to write intermediates/results");
                            Console.WriteLine("-BINMC0WASM <path> -- (optional) Override OpenWatcom wasm path (default: wasm)");
                            Console.WriteLine("-BINMC0WLINK <path> -- (optional) Override OpenWatcom wlink path (default: wlink)");
                            Console.WriteLine("-BINMC1IN <file.mc1> -- Parse MC1 (deterministic sugar) and desugar into MC0 text");
                            Console.WriteLine("-BINMC1OUT <file.mc0> -- (with -BINMC1IN) Write desugared MC0 output");
                            Console.WriteLine("-BINMC1EXPECT <file.mc0> -- (optional) Verify desugared MC0 matches expected by origin/bytes stream");
                            Console.WriteLine("-BINMC1PROVEIN <file.mc1> -- Prove chain: MC1 desugars to same MC0 as promoted asm (and optionally rebuild byte-compare)");
                            Console.WriteLine("-BINMC1PROVEASM <file.promoted.asm> -- (with -BINMC1PROVEIN) Baseline promoted asm");
                            Console.WriteLine("-BINMC1PROVEORIG <file.exe> -- (optional) Also run MC0 rebuild verifier against original exe");
                            Console.WriteLine("-BINMC1PROVEOUTDIR <dir> -- (optional) Out dir for rebuild intermediates");
                            Console.WriteLine("-BINTRACEASM <file.asm> -- Trace lifted BIN16 bytes with Unicorn and write an instruction trace");
                            Console.WriteLine("-BINTRACEOUT <file.txt> -- (with -BINTRACEASM) Output trace file");
                            Console.WriteLine("-BINTRACESTART <hex> -- (with -BINTRACEASM) Logical start address for tracing window (same as listing comment addresses)");
                            Console.WriteLine("-BINTRACEWINDOW <hex> -- (with -BINTRACEASM) Trace window size (default 0x10000; max 0x10000)");
                            Console.WriteLine("-BINTRACESTEPS <n> -- (with -BINTRACEASM) Max instruction steps to execute (default 10000)");
                            Console.WriteLine("-UNICORNPROBE -- Debug: probe Unicorn P/Invoke load + uc_open/uc_close");
                            Console.WriteLine("-BINDIRREASM <inDir> <outDir> -- Batch export BIN16 reassembly (db) + JSON for all non-MZ files in <inDir> (skips MZ/NE/LE/PE); uses -BINORG for org");
                            Console.WriteLine("-BINDIRREASMWASM <inDir> <outDir> -- Batch export BIN16 reassembly in OpenWatcom WASM/MASM-compatible syntax (db + JSON)");
                            Console.WriteLine("-BINDIREXT <ext> -- (with -BINDIRREASM) Only export files with this extension (example: .ovl)");
                            Console.WriteLine("-MINIMAL -- Minimal Disassembler Output");
                            Console.WriteLine(
                                "-ANALYSIS -- Additional Analysis on Imported Functions (if available)");
                            Console.WriteLine(
                                "-STRINGS -- Output all strings found in DATA segments at end of Disassembly");
                            Console.WriteLine(
                                "-DOSVER <v> -- Target DOS version for interrupt annotations (example: 6.22, 7.10)");
                            Console.WriteLine(
                                "-LEFULL -- (LE inputs) Disassemble executable objects from the start (can be very large)");
                            Console.WriteLine(
                                "-LEBYTES <n> -- (LE inputs) Limit disassembly to n bytes from start offset");
                            Console.WriteLine(
                                "-LEFIXUPS -- (LE inputs) Annotate output with best-effort LE fixups/import targets");
                            Console.WriteLine(
                                "-LEGLOBALS -- (LE inputs) Emit g_XXXXXXXX EQU 0xXXXXXXXX from disp32 fixups + rewrite operands (LLM-friendly)");
                            Console.WriteLine(
                                "-LEINSIGHTS -- (LE inputs) Best-effort function/CFG/xref/stack-var/string analysis (more LLM-friendly)");
                            Console.WriteLine(
                                "-LEIDAMAP <file.map> -- (LE inputs) Import IDA .map names and append as hints (best-effort)");
                            Console.WriteLine(
                                "-LEBNIR <file.txt> -- (LE inputs) Import Binary Ninja IR text names and append as hints (best-effort)");
                            Console.WriteLine(
                                "-LERENDERLIMIT <n> -- (LE inputs) Max instructions per object to emit (0 = no instruction render; insights-only)");
                            Console.WriteLine(
                                "-LEJOBS <n> -- (LE inputs) Parallel jobs for insights passes (default 1; try 8 on an 8-core machine)");
                            Console.WriteLine(
                                "-LEDECOMP -- (LE inputs) Emit best-effort pseudo-C (builds on LE insights/symbolization)");
                            Console.WriteLine(
                                  "-LECHUNKS <n> -- (LE inputs) Split decompile output into ~n translation units (b0.c..bN.c) (requires -O)");
                            Console.WriteLine(
                                "-LEDECOMPASM <file.asm> -- Decompile from an existing LE .asm output (fast iteration; skips LE disassembly)");
                            Console.WriteLine(
                                "-LEDECOMPCACHEASM -- (LE inputs) Cache rendered LE .asm next to -O and reuse it on future -LEDECOMP runs (much faster after first run; requires -O)");
                            Console.WriteLine(
                                "-LEUNWRAP -- (EURO96/EUROBLST-style) If input is an MZ stub with a BW overlay header, unwrap the embedded bound MZ+LE and run the LE pipeline on that payload");
                            Console.WriteLine(
                                "-LESCANMZ -- (LE detection) Opt-in fallback: scan only the MZ overlay region for an LE header if e_lfanew/BW detection fails (may be slower; avoids most false positives)");
                            Console.WriteLine(
                                "-LEFUNC <func_XXXXXXXX|XXXXXXXX|0xXXXXXXXX> -- Only emit a single function (works with -LEDECOMP; useful for patching stubs; slicing omits loader/main.c)");
                            Console.WriteLine(
                                "-LEFIXDUMP [maxPages] -- (LE inputs) Dump raw fixup pages + decoding hints (writes <out>.fixups.txt if -O is used)");
                            Console.WriteLine(
                                "-LECALLGRAPHDOT <file.dot> -- (LE inputs) Export a best-effort function call graph in Graphviz DOT format (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LECALLGRAPHJSON <file.json> -- (LE inputs) Export a best-effort function call graph in JSON format (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LECFGDOT <file.dot> -- (LE inputs) Export a best-effort per-function CFG in Graphviz DOT format (implies -LEINSIGHTS; uses -LEFUNC if provided, else entry function)");
                            Console.WriteLine(
                                "-LECFGALLDOT <file.dot> -- (LE inputs) Export a best-effort whole-program CFG index in Graphviz DOT format (clusters per function; implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LECFGALLJSON <file.json> -- (LE inputs) Export a best-effort whole-program CFG index in JSON format (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LEREPORTJSON <file.json> -- (LE inputs) Export a compact LE analysis report (entry + counts + header/object/import/fixup summary) in JSON format (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LEREPORTFUNCS -- (LE inputs) Include per-function calls/globals/strings in the -LEREPORTJSON payload (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-LEFIXUPSJSON <file.json> -- (LE inputs) Export a best-effort normalized LE fixup table in JSON format");
                            Console.WriteLine(
                                "-LEIMPORTSJSON <file.json> -- (LE inputs) Export LE import map + best-effort xrefs (implies -LEINSIGHTS for function ownership mapping)");
                            Console.WriteLine(
                                "-LEREACHJSON <file.json> -- (LE inputs) Export reachability-based code marking (reachable code ranges vs data candidates)");
                            Console.WriteLine(
                                "-MZFULL -- (MZ inputs) Disassemble from entrypoint to end of load module");
                            Console.WriteLine(
                                "-MZBYTES <n> -- (MZ inputs) Limit disassembly to n bytes from entrypoint");
                            Console.WriteLine(
                                "-MZINSIGHTS -- (MZ inputs) Best-effort labels/xrefs/strings for 16-bit MZ binaries");
                            Console.WriteLine(
                                "-MZREASM <file.asm> -- (MZ inputs) Export byte-perfect NASM -f bin reconstruction (db/dw), preserving relocation table bytes");
                            Console.WriteLine(
                                "-MZREASMJSON <file.json> -- (MZ inputs) Export MZ header + relocation metadata for the -MZREASM output");
                            Console.WriteLine(
                                "-MZREASMWASM <file.asm> -- (MZ inputs) Export byte-perfect reassembly in OpenWatcom WASM/MASM-compatible syntax (db/dw + 8086 directives)");
                            Console.WriteLine(
                                "-BORLAND -- Toolchain hint: use Borland/Turbo-era heuristics (best-effort; currently impacts MZ output)");
                            Console.WriteLine(
                                "-WATCOM -- Toolchain hint: use Watcom-era heuristics (best-effort; currently impacts MZ output)");
                            Console.WriteLine(
                                "-INTSKELETON <out.json> -- Generate an editable interrupt JSON skeleton from dosre.unknown-ints.txt");
                            Console.WriteLine(
                                "-INTSKELETON <in.txt> <out.json> -- Same, but read from a specific input file");
                            Console.WriteLine(
                                "-SPLITKB <n> -- (with -O) Split output into ~n KB chunks (out.001.asm, out.002.asm, ...)");
                            Console.WriteLine(
                                "-MACROS -- Replace repeated straight-line chunks with macros (best-effort, readability)");
                            return;
                    }
                }

                // Batch BIN16 reassembly export: bypass input file requirements and all format detection/disassembly.
                if (!string.IsNullOrWhiteSpace(_binDirReasmInDir) ||
                    !string.IsNullOrWhiteSpace(_binDirReasmOutDir) ||
                    !string.IsNullOrWhiteSpace(_binDirReasmOutDirWasm))
                {
                    var wantNasm = !string.IsNullOrWhiteSpace(_binDirReasmOutDir);
                    var wantWasm = !string.IsNullOrWhiteSpace(_binDirReasmOutDirWasm);

                    if (string.IsNullOrWhiteSpace(_binDirReasmInDir) || (!wantNasm && !wantWasm))
                        throw new Exception("Error: -BINDIRREASM requires <inDir> <outDir> (or use -BINDIRREASMWASM <inDir> <outDir>)");
                    if (!Directory.Exists(_binDirReasmInDir))
                        throw new Exception($"Error: input directory does not exist: {_binDirReasmInDir}");

                    string normExt = null;
                    if (!string.IsNullOrWhiteSpace(_binDirReasmExt))
                    {
                        normExt = _binDirReasmExt.Trim();
                        if (!normExt.StartsWith('.'))
                            normExt = "." + normExt;
                        normExt = normExt.ToLowerInvariant();
                    }

                    if (wantNasm)
                        Directory.CreateDirectory(_binDirReasmOutDir);
                    if (wantWasm)
                        Directory.CreateDirectory(_binDirReasmOutDirWasm);

                    static bool HasMZHeader(string path)
                    {
                        try
                        {
                            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                            if (fs.Length < 2)
                                return false;
                            var b0 = fs.ReadByte();
                            var b1 = fs.ReadByte();
                            return b0 == 'M' && b1 == 'Z';
                        }
                        catch
                        {
                            return false;
                        }
                    }

                    var ok = 0;
                    var skipped = 0;
                    var skippedEmpty = 0;
                    var failed = 0;

                    foreach (var file in Directory.EnumerateFiles(_binDirReasmInDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        try
                        {
                            var len = new FileInfo(file).Length;
                            if (len == 0)
                            {
                                skippedEmpty++;
                                continue;
                            }
                        }
                        catch
                        {
                            // If we can't stat the file, just attempt export and let it report a failure.
                        }

                        if (!string.IsNullOrWhiteSpace(normExt))
                        {
                            var ext = (Path.GetExtension(file) ?? string.Empty).ToLowerInvariant();
                            if (ext != normExt)
                                continue;
                        }

                        if (HasMZHeader(file))
                        {
                            skipped++;
                            continue;
                        }

                        var baseName = Path.GetFileName(file);

                        var fileOk = true;

                        if (wantNasm)
                        {
                            var outAsm = Path.Combine(_binDirReasmOutDir, baseName + ".bin16.reasm.asm");
                            var outJson = Path.Combine(_binDirReasmOutDir, baseName + ".bin16.reasm.json");
                            if (!Bin16Disassembler.TryExportReassembly(file, _binOrigin, outAsm, outJson, out var reasmErr))
                            {
                                fileOk = false;
                                _logger.Warn($"-BINDIRREASM failed for {file}: {reasmErr}");
                            }
                        }

                        if (wantWasm)
                        {
                            var outAsm = Path.Combine(_binDirReasmOutDirWasm, baseName + ".bin16.reasm.asm");
                            var outJson = Path.Combine(_binDirReasmOutDirWasm, baseName + ".bin16.reasm.json");
                            if (!Bin16Disassembler.TryExportReassembly(file, _binOrigin, outAsm, outJson, wasmCompat: true, out var reasmErr))
                            {
                                fileOk = false;
                                _logger.Warn($"-BINDIRREASMWASM failed for {file}: {reasmErr}");
                            }
                        }

                        if (fileOk)
                            ok++;
                        else
                            failed++;
                    }

                    if (failed > 0)
                        throw new Exception($"Error: -BINDIRREASM completed with failures (ok={ok} skipped_mz={skipped} skipped_empty={skippedEmpty} failed={failed})");

                    _logger.Info($"{DateTime.Now} -BINDIRREASM done (ok={ok} skipped_mz={skipped} skipped_empty={skippedEmpty} origin=0x{_binOrigin:X})");
                    return;
                }

                // BINLIFTASM mode: lift a byte-authoritative promoted asm listing into a 1:1 crude AST and C data.
                // This mode is independent of -I and any binary format.
                if (!string.IsNullOrWhiteSpace(_binLiftAsm))
                {
                    if (string.IsNullOrWhiteSpace(_binLiftJson) && string.IsNullOrWhiteSpace(_binLiftH) && string.IsNullOrWhiteSpace(_binLiftC))
                        throw new Exception("Error: -BINLIFTASM requires at least one output: -BINLIFTJSON and/or -BINLIFTH and/or -BINLIFTC");

                    Bin16AsmLifter.LiftToFiles(_binLiftAsm, _binLiftJson, _binLiftC, _binLiftH);

                    if (!string.IsNullOrWhiteSpace(_binLiftJson)) _logger.Info($"{DateTime.Now} Wrote BINLIFT JSON to {_binLiftJson}");
                    if (!string.IsNullOrWhiteSpace(_binLiftH)) _logger.Info($"{DateTime.Now} Wrote BINLIFT header to {_binLiftH}");
                    if (!string.IsNullOrWhiteSpace(_binLiftC)) _logger.Info($"{DateTime.Now} Wrote BINLIFT C to {_binLiftC}");
                    return;
                }

                // BINMC0ASM mode: lift promoted asm into MC0 (Machine-C Level 0) and optionally re-emit a db listing.
                // This mode is independent of -I and any binary format.
                if (!string.IsNullOrWhiteSpace(_binMc0Asm))
                {
                    if (string.IsNullOrWhiteSpace(_binMc0Out) && string.IsNullOrWhiteSpace(_binMc0Json) && string.IsNullOrWhiteSpace(_binMc0Reasm))
                        throw new Exception("Error: -BINMC0ASM requires at least one output: -BINMC0OUT and/or -BINMC0JSON and/or -BINMC0REASM");

                    Bin16Mc0.LiftToFiles(_binMc0Asm, _binMc0Out, _binMc0Json, _binMc0Reasm);

                    if (!string.IsNullOrWhiteSpace(_binMc0Out)) _logger.Info($"{DateTime.Now} Wrote BINMC0 text to {_binMc0Out}");
                    if (!string.IsNullOrWhiteSpace(_binMc0Json)) _logger.Info($"{DateTime.Now} Wrote BINMC0 JSON to {_binMc0Json}");
                    if (!string.IsNullOrWhiteSpace(_binMc0Reasm)) _logger.Info($"{DateTime.Now} Wrote BINMC0 re-asm to {_binMc0Reasm}");
                    return;
                }

                // BINMC0VERIFY: end-to-end rebuild and byte-compare.
                if (!string.IsNullOrWhiteSpace(_binMc0VerifyAsm))
                {
                    if (string.IsNullOrWhiteSpace(_binMc0VerifyOrig))
                        throw new Exception("Error: -BINMC0VERIFYASM requires -BINMC0VERIFYORIG <file.exe>");

                    var opts = new Bin16Mc0Verifier.VerifyOptions
                    {
                        OutDir = _binMc0VerifyOutDir,
                    };
                    if (!string.IsNullOrWhiteSpace(_binMc0WasmPath)) opts.WasmPath = _binMc0WasmPath;
                    if (!string.IsNullOrWhiteSpace(_binMc0WlinkPath)) opts.WlinkPath = _binMc0WlinkPath;

                    var res = Bin16Mc0Verifier.VerifyPromotedAsmBuildsOriginalExe(_binMc0VerifyAsm, _binMc0VerifyOrig, opts);

                    _logger.Info($"BINMC0VERIFY byte_equal={res.ByteEqual} orig_size={res.OriginalSize} reb_size={res.RebuiltSize}");
                    _logger.Info($"BINMC0VERIFY sha256 orig={res.OriginalSha256}");
                    _logger.Info($"BINMC0VERIFY sha256 reb ={res.RebuiltSha256}");
                    if (!res.ByteEqual && !string.IsNullOrWhiteSpace(res.FirstDiff))
                        _logger.Warn($"BINMC0VERIFY first_diff {res.FirstDiff}");
                    _logger.Info($"BINMC0VERIFY rebuilt {res.RebuiltExe}");
                    return;
                }

                // BINMC1: desugar MC1 to MC0, optionally verify identity vs expected MC0.
                if (!string.IsNullOrWhiteSpace(_binMc1In))
                {
                    if (string.IsNullOrWhiteSpace(_binMc1Out))
                        throw new Exception("Error: -BINMC1IN requires -BINMC1OUT <file.mc0>");

                    var mc1 = Mc1.Parse(_binMc1In);
                    var mc0Text = Mc1.DesugarToMc0Text(mc1);
                    File.WriteAllText(_binMc1Out, mc0Text);
                    _logger.Info($"{DateTime.Now} Wrote BINMC1 desugared MC0 to {_binMc1Out}");

                    if (!string.IsNullOrWhiteSpace(_binMc1Expect))
                    {
                        var expected = Bin16Mc0.ParseMc0Text(File.ReadAllLines(_binMc1Expect), _binMc1Expect);
                        var actual = Bin16Mc0.ParseMc0Text(File.ReadAllLines(_binMc1Out), _binMc1Out);
                        Bin16Mc0.VerifyByteIdentity(expected, actual);
                        _logger.Info($"{DateTime.Now} BINMC1EXPECT OK (origin/bytes stream identical)");
                    }

                    return;
                }

                // BINMC1LIFT: lift promoted asm into MC1 (auto-sugar).
                if (!string.IsNullOrWhiteSpace(_binMc1LiftAsm))
                {
                    if (string.IsNullOrWhiteSpace(_binMc1LiftOut))
                        throw new Exception("Error: -BINMC1LIFTASM requires -BINMC1LIFTOUT <file.mc1>");

                    Bin16Mc1Lifter.LiftPromotedAsmToFile(_binMc1LiftAsm, _binMc1LiftOut);
                    _logger.Info($"{DateTime.Now} Wrote BINMC1 lifted MC1 to {_binMc1LiftOut}");
                    return;
                }

                // BINMC1PROVE: chain proof for deterministic lowering.
                if (!string.IsNullOrWhiteSpace(_binMc1ProveIn))
                {
                    if (string.IsNullOrWhiteSpace(_binMc1ProveAsm))
                        throw new Exception("Error: -BINMC1PROVEIN requires -BINMC1PROVEASM <file.promoted.asm>");

                    var opts = new Bin16McChainProof.ProveOptions
                    {
                        SkipRebuildCompare = string.IsNullOrWhiteSpace(_binMc1ProveOrig),
                        OutDir = _binMc1ProveOutDir,
                        WasmPath = string.IsNullOrWhiteSpace(_binMc0WasmPath) ? "wasm" : _binMc0WasmPath,
                        WlinkPath = string.IsNullOrWhiteSpace(_binMc0WlinkPath) ? "wlink" : _binMc0WlinkPath,
                    };

                    var res = Bin16McChainProof.ProveMc1AgainstPromotedAndOriginal(_binMc1ProveIn, _binMc1ProveAsm, _binMc1ProveOrig, opts);

                    _logger.Info($"BINMC1PROVE mc1_to_mc0_identity={res.Mc1DesugarsToSameMc0} stream_sha256={res.Mc0StreamSha256} stmts={res.Mc0StatementCount}");
                    if (res.Mc0RebuildByteEqual.HasValue)
                    {
                        _logger.Info($"BINMC1PROVE mc0_rebuild_byte_equal={res.Mc0RebuildByteEqual.Value}");
                        _logger.Info($"BINMC1PROVE sha256 orig={res.Mc0RebuildOriginalSha256}");
                        _logger.Info($"BINMC1PROVE sha256 reb ={res.Mc0RebuildRebuiltSha256}");
                        if (!res.Mc0RebuildByteEqual.Value && !string.IsNullOrWhiteSpace(res.FirstDiff))
                            _logger.Warn($"BINMC1PROVE first_diff {res.FirstDiff}");
                        if (!string.IsNullOrWhiteSpace(res.RebuiltExe))
                            _logger.Info($"BINMC1PROVE rebuilt {res.RebuiltExe}");
                    }
                    return;
                }

                if (_bUnicornProbe)
                {
                    DOSRE.Unicorn.UnicornProbe.Run();
                    return;
                }

                // BINTRACEASM mode: execute a window of lifted BIN16 bytes using Unicorn and emit an instruction trace.
                // This mode is independent of -I and any binary format.
                if (!string.IsNullOrWhiteSpace(_binTraceAsm))
                {
                    if (string.IsNullOrWhiteSpace(_binTraceOut))
                        throw new Exception("Error: -BINTRACEASM requires -BINTRACEOUT <file.txt>");
                    if (!_binTraceStart.HasValue)
                        throw new Exception("Error: -BINTRACEASM requires -BINTRACESTART <hex>");

                    var opts = new Bin16UnicornTracer.TraceOptions
                    {
                        StartAddr = _binTraceStart.Value,
                        WindowSize = _binTraceWindow,
                        MaxInstructions = (nuint)_binTraceSteps,
                    };

                    Bin16UnicornTracer.TracePromotedAsmToFile(_binTraceAsm, _binTraceOut, opts);
                    _logger.Info($"{DateTime.Now} Wrote BINTRACE to {_binTraceOut}");
                    return;
                }

                //Verify Input File is Valid (unless decompiling from an asm file)
                if (!string.IsNullOrWhiteSpace(_leDecompileAsmFile))
                {
                    if (!File.Exists(_leDecompileAsmFile))
                        throw new Exception("Error: Please specify a valid -LEDECOMPASM file");
                }
                else
                {
                    if (string.IsNullOrEmpty(_sInputFile) || !File.Exists(_sInputFile))
                        throw new Exception("Error: Please specify a valid input file");
                }

                if (_bLeDecompCacheAsm && string.IsNullOrWhiteSpace(_sOutputFile))
                    throw new Exception("Error: -LEDECOMPCACHEASM requires -O <out> so the cache .asm path can be derived");

                // Apply DOS version selection globally for interrupt DB lookups.
                DosInterruptDatabase.SetCurrentDosVersionGlobal(_dosVersion);

                // Apply toolchain hint globally so toolchain-specific interrupt overlays can be selected.
                DosInterruptDatabase.SetCurrentToolchainHintGlobal(_toolchainHint);

                // Optional: unwrap BW overlay containers (MZ stub + BW overlay header pointing at an embedded bound MZ+LE).
                // This is useful for executables where the *real* protected-mode payload is not directly at e_lfanew.
                if (_bLeUnwrap && string.IsNullOrWhiteSpace(_leDecompileAsmFile))
                {
                    if (TryUnwrapBwBoundExecutable(_sInputFile, _sOutputFile, out var unwrappedPath, out var unwrapNote, out var unwrapError))
                    {
                        _logger.Info(unwrapNote);
                        _sInputFile = unwrappedPath;
                    }
                    else if (!string.IsNullOrWhiteSpace(unwrapError))
                    {
                        _logger.Warn($"-LEUNWRAP requested but unwrap failed: {unwrapError}");
                    }
                }

                // Flat binary mode: bypass all format detection and render a straightforward 16-bit decode.
                if (_bBin16)
                {
                    if (!string.IsNullOrEmpty(_binReasmAsm) || !string.IsNullOrEmpty(_binReasmAsmWasm) || !string.IsNullOrEmpty(_binReasmJson))
                    {
                        if (!string.IsNullOrEmpty(_binReasmAsm) || !string.IsNullOrEmpty(_binReasmJson))
                        {
                            if (Bin16Disassembler.TryExportReassembly(_sInputFile, _binOrigin, _binReasmAsm, _binReasmJson, out var reasmErr))
                            {
                                if (!string.IsNullOrEmpty(_binReasmAsm))
                                    _logger.Info($"{DateTime.Now} Wrote BIN16 reassembly export to {_binReasmAsm}");
                                if (!string.IsNullOrEmpty(_binReasmJson))
                                    _logger.Info($"{DateTime.Now} Wrote BIN16 reassembly metadata to {_binReasmJson}");
                            }
                            else
                            {
                                throw new Exception($"Error: -BINREASM export failed: {reasmErr}");
                            }
                        }

                        if (!string.IsNullOrEmpty(_binReasmAsmWasm))
                        {
                            if (Bin16Disassembler.TryExportReassembly(_sInputFile, _binOrigin, _binReasmAsmWasm, outJsonFile: null, wasmCompat: true, out var reasmErr))
                            {
                                _logger.Info($"{DateTime.Now} Wrote BIN16 reassembly export (WASM) to {_binReasmAsmWasm}");
                            }
                            else
                            {
                                throw new Exception($"Error: -BINREASMWASM export failed: {reasmErr}");
                            }
                        }
                    }

                    var emitInstr = _bBinInstr && !_bBinInstrDb;
                    var emitInstrSafe = emitInstr && _bBinInstrSafe;
                    var safeFallbacks = Bin16Disassembler.Bin16SafeMnemonicFallbacks.None;
                    if (_bBinInstrSafeRegReg)
                        safeFallbacks |= Bin16Disassembler.Bin16SafeMnemonicFallbacks.RegReg;
                    if (_bBinInstrSafeImm)
                        safeFallbacks |= Bin16Disassembler.Bin16SafeMnemonicFallbacks.ImmWidth;
                    if (_bBinInstrSafeJumps)
                        safeFallbacks |= Bin16Disassembler.Bin16SafeMnemonicFallbacks.Jumps;

                    if (!Bin16Disassembler.TryDisassembleToString(_sInputFile, _binOrigin, _binBytesLimit, _bBinMasmCompat, _bBinInsights, _bBinStrLabels, emitInstr, emitInstrSafe, safeFallbacks, _bBinInstrSafeForceJumps, _bBinInstrDb, _bBinMap, _bBin16LooseInt, _bBin16LooseIo, out var binOut, out var binErr))
                        throw new Exception(binErr);

                    if (string.IsNullOrEmpty(_sOutputFile))
                    {
                        if (_splitKb.HasValue)
                            _logger.Warn("Warning: -splitkb requires -o, ignoring");
                        Console.WriteLine(binOut);
                    }
                    else
                    {
                        if (_splitKb.HasValue)
                            WriteSplitFiles(_sOutputFile, binOut, _splitKb.Value);
                        else
                            File.WriteAllText(_sOutputFile, binOut);
                    }

                    _logger.Info($"{DateTime.Now} Done!");
                    return;
                }

                //LE/DOS4GW support (minimal): bypass NE-specific pipeline
                //NOTE: This tool was originally NE-only; LE support does not include relocations/import analysis.
                bool leOk;
                string leOutput;
                string leError;

                var wantLeCallGraph = !string.IsNullOrWhiteSpace(_leCallGraphDot) || !string.IsNullOrWhiteSpace(_leCallGraphJson);
                var wantLeCfgDot = !string.IsNullOrWhiteSpace(_leCfgDot);
                var wantLeCfgAllDot = !string.IsNullOrWhiteSpace(_leCfgAllDot);
                var wantLeCfgAllJson = !string.IsNullOrWhiteSpace(_leCfgAllJson);
                var wantLeReportJson = !string.IsNullOrWhiteSpace(_leReportJson);
                var wantLeFixupsJson = !string.IsNullOrWhiteSpace(_leFixupsJson);
                var wantLeImportsJson = !string.IsNullOrWhiteSpace(_leImportsJson);
                var wantLeReachJson = !string.IsNullOrWhiteSpace(_leReachJson);
                var leInsightsForRun = _bLeInsights || wantLeCallGraph || wantLeCfgDot || wantLeCfgAllDot || wantLeCfgAllJson || wantLeReportJson || wantLeImportsJson;

                static string DetectExeFormat(string path)
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                            return null;

                        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                        if (fs.Length < 2)
                            return "Unknown";

                        Span<byte> hdr = stackalloc byte[64];
                        var read = fs.Read(hdr);
                        if (read < 2)
                            return "Unknown";

                        static bool IsSig(ReadOnlySpan<byte> data, int length, int off, byte a, byte b)
                            => off + 1 < length && data[off] == a && data[off + 1] == b;

                        if (IsSig(hdr, read, 0, (byte)'M', (byte)'Z'))
                        {
                            if (read < 0x40)
                                return "MZ";

                            var lfanew = BitConverter.ToUInt32(hdr.Slice(0x3C, 4));
                            if (lfanew == 0)
                                return "MZ";
                            if (lfanew > (ulong)fs.Length || lfanew + 4 > (ulong)fs.Length)
                                return "MZ";

                            fs.Position = lfanew;
                            Span<byte> sig = stackalloc byte[4];
                            var sigRead = fs.Read(sig);
                            if (sigRead >= 2)
                            {
                                if (sigRead >= 4 && sig[0] == (byte)'P' && sig[1] == (byte)'E' && sig[2] == 0 && sig[3] == 0)
                                    return "PE";
                                if (sig[0] == (byte)'N' && sig[1] == (byte)'E')
                                    return "NE";
                                if (sig[0] == (byte)'L' && sig[1] == (byte)'E')
                                    return "LE";
                                if (sig[0] == (byte)'L' && sig[1] == (byte)'X')
                                    return "LX";
                            }

                            return "MZ";
                        }

                        if (IsSig(hdr, read, 0, (byte)'N', (byte)'E')) return "NE";
                        if (IsSig(hdr, read, 0, (byte)'L', (byte)'E')) return "LE";
                        if (IsSig(hdr, read, 0, (byte)'L', (byte)'X')) return "LX";
                        if (read >= 4 && hdr[0] == (byte)'P' && hdr[1] == (byte)'E' && hdr[2] == 0 && hdr[3] == 0) return "PE";

                        return "Unknown";
                    }
                    catch
                    {
                        return "Unknown";
                    }
                }

                static string ChooseLeOutput(Dictionary<string, string> files)
                {
                    if (files == null || files.Count == 0)
                        return string.Empty;
                    if (files.TryGetValue("blst.c", out var blst))
                        return blst;
                    if (files.TryGetValue("main.c", out var main))
                        return main;
                    return files.Values.First();
                }

                Dictionary<string, string> leDecompFiles = null;

                if (_bLeDecompile && !string.IsNullOrWhiteSpace(_leDecompileAsmFile))
                {
                    if (wantLeCallGraph)
                        _logger.Warn("Warning: -LECALLGRAPH* is not supported with -LEDECOMPASM (no LE decode pass). Run without -LEDECOMPASM to export call graphs.");
                    if (wantLeCfgDot)
                        _logger.Warn("Warning: -LECFGDOT is not supported with -LEDECOMPASM (no LE decode pass). Run without -LEDECOMPASM to export CFG.");
                    if (wantLeCfgAllDot)
                        _logger.Warn("Warning: -LECFGALLDOT is not supported with -LEDECOMPASM (no LE decode pass). Run without -LEDECOMPASM to export CFG.");
                    if (wantLeCfgAllJson)
                        _logger.Warn("Warning: -LECFGALLJSON is not supported with -LEDECOMPASM (no LE decode pass). Run without -LEDECOMPASM to export CFG.");
                    if (wantLeReportJson)
                        _logger.Warn("Warning: -LEREPORTJSON is not supported with -LEDECOMPASM (no LE decode pass). Run without -LEDECOMPASM to export the report.");
                    if (wantLeFixupsJson)
                        _logger.Warn("Warning: -LEFIXUPSJSON is not supported with -LEDECOMPASM (no input file to parse). Run without -LEDECOMPASM to export fixups.");
                    if (wantLeImportsJson)
                        _logger.Warn("Warning: -LEIMPORTSJSON is not supported with -LEDECOMPASM (no input file to parse / no analysis). Run without -LEDECOMPASM to export imports.");
                    if (wantLeReachJson)
                        _logger.Warn("Warning: -LEREACHJSON is not supported with -LEDECOMPASM (no input file to parse / no decode pass). Run without -LEDECOMPASM to export reachability.");
                    leOk = LEDisassembler.TryDecompileToMultipartFromAsmFile(_leDecompileAsmFile, _leOnlyFunction, _leChunks, out leDecompFiles, out leError);
                    leOutput = leOk ? ChooseLeOutput(leDecompFiles) : string.Empty;
                }
                else if (_bLeDecompile && _bLeDecompCacheAsm)
                {
                    var cacheAsmPath = Path.ChangeExtension(_sOutputFile, ".asm");
                    var cacheDir = Path.GetDirectoryName(cacheAsmPath);
                    if (!string.IsNullOrWhiteSpace(cacheDir))
                        Directory.CreateDirectory(cacheDir);

                    if (File.Exists(cacheAsmPath))
                    {
                        _logger.Info($"LE decompile: using cached asm {cacheAsmPath}");
                        leOk = LEDisassembler.TryDecompileToMultipartFromAsmFile(cacheAsmPath, _leOnlyFunction, _leChunks, chunkSizeIsCount: true, out leDecompFiles, out leError);
                        leOutput = leOk ? ChooseLeOutput(leDecompFiles) : string.Empty;
                    }
                    else
                    {
                        if (_leRenderLimit.HasValue)
                            _logger.Warn("Warning: -LERENDERLIMIT is ignored for -LEDECOMPCACHEASM (needs full rendered .asm)");

                        _logger.Info($"LE decompile: generating asm cache {cacheAsmPath} (first run)");

                        // We need a fully rendered .asm to feed the pseudo-C parser.
                        var asmOk = LEDisassembler.TryDisassembleToString(
                            _sInputFile,
                            _bLeFull,
                            _leBytesLimit,
                            leRenderLimit: null,
                            leJobs: _leJobs,
                            leFixups: _bLeFixups,
                            leGlobals: _bLeGlobals,
                            leInsights: true,
                            _toolchainHint,
                            _leStartLinear,
                            _bLeScanMz,
                            _leIdaMapFile,
                            _leBinaryNinjaIrFile,
                            out var asm,
                            out leError);

                        if (!asmOk)
                        {
                            leOk = false;
                            leOutput = string.Empty;
                        }
                        else
                        {
                            File.WriteAllText(cacheAsmPath, asm);
                            leOk = LEDisassembler.TryDecompileToMultipartFromAsm(asm, _leOnlyFunction, _leChunks, chunkSizeIsCount: true, out leDecompFiles, out leError);
                            leOutput = leOk ? ChooseLeOutput(leDecompFiles) : string.Empty;
                        }
                    }
                }
                else
                {
                    if (_bLeDecompile)
                    {
                        // If -LEFUNC is specified, route through the asm->pseudo-C path so we can slice to a single function.
                        // This intentionally skips generating loader/main.c and emits only pseudo-C for the requested function.
                        if (!string.IsNullOrWhiteSpace(_leOnlyFunction))
                        {
                            var asmOk = LEDisassembler.TryDisassembleToString(
                                _sInputFile,
                                _bLeFull,
                                _leBytesLimit,
                                _leRenderLimit,
                                _leJobs,
                                _bLeFixups,
                                _bLeGlobals,
                                leInsights: true,
                                _toolchainHint,
                                _leStartLinear,
                                _bLeScanMz,
                                _leIdaMapFile,
                                _leBinaryNinjaIrFile,
                                out var asm,
                                out leError);

                            if (!asmOk)
                            {
                                leOk = false;
                                leDecompFiles = null;
                                leOutput = string.Empty;
                            }
                            else
                            {
                                leOk = LEDisassembler.TryDecompileToMultipartFromAsm(asm, _leOnlyFunction, _leChunks, chunkSizeIsCount: true, out leDecompFiles, out leError);
                                leOutput = leOk ? ChooseLeOutput(leDecompFiles) : string.Empty;
                            }
                        }
                        else
                        {
                            leOk = LEDisassembler.TryDecompileToMultipart(_sInputFile, _bLeFull, _leBytesLimit, _bLeFixups, _bLeGlobals, _bLeInsights, _toolchainHint, _leChunks, chunkSizeIsCount: true, out leDecompFiles, out leError);
                            leOutput = leOk ? ChooseLeOutput(leDecompFiles) : string.Empty;
                        }
                    }
                    else
                    {
                        leOk = LEDisassembler.TryDisassembleToString(_sInputFile, _bLeFull, _leBytesLimit, _leRenderLimit, _leJobs, _bLeFixups, _bLeGlobals, leInsightsForRun, _toolchainHint, _leStartLinear, _bLeScanMz, _leIdaMapFile, _leBinaryNinjaIrFile, out leOutput, out leError);
                    }
                }

                if (leOk)
                {
                    if (_leExportObjIndex.HasValue && !string.IsNullOrWhiteSpace(_leExportObjFile))
                    {
                        if (LEDisassembler.TryExportObjectBytes(_sInputFile, _bLeScanMz, _leExportObjIndex.Value, _leExportObjFile, out var expErr))
                        {
                            _logger.Info($"LE: Exported object {_leExportObjIndex.Value} bytes to {_leExportObjFile}");
                        }
                        else
                        {
                            _logger.Warn($"Warning: failed to export object {_leExportObjIndex.Value}: {expErr}");
                        }
                    }

                    if (wantLeCallGraph)
                    {
                        var analysis = LEDisassembler.GetLastAnalysis();
                        if (analysis == null || analysis.Functions == null || analysis.Functions.Count == 0)
                        {
                            _logger.Warn("Warning: -LECALLGRAPH* requested but no LE analysis was captured (try enabling -LEINSIGHTS and avoid -LERENDERLIMIT 0 on first run if needed)");
                        }
                        else
                        {
                            string FuncName(uint addr) => $"func_{addr:X8}";

                            if (!string.IsNullOrWhiteSpace(_leCallGraphDot))
                            {
                                var dot = new StringBuilder();
                                dot.AppendLine("digraph le_callgraph {");
                                dot.AppendLine("  rankdir=LR;");
                                dot.AppendLine("  node [shape=box,fontname=\"monospace\"];");
                                dot.AppendLine($"  \"{FuncName(analysis.EntryLinear)}\" [shape=doubleoctagon,label=\"{FuncName(analysis.EntryLinear)}\\n(entry)\"]; ");

                                foreach (var fn in analysis.Functions.Values.OrderBy(f => f.Start))
                                {
                                    dot.AppendLine($"  \"{FuncName(fn.Start)}\" [label=\"{FuncName(fn.Start)}\\nins={fn.InstructionCount} blocks={fn.BlockCount}\"]; ");
                                }

                                foreach (var fn in analysis.Functions.Values.OrderBy(f => f.Start))
                                {
                                    if (fn.Calls == null) continue;
                                    foreach (var callee in fn.Calls.OrderBy(x => x))
                                        dot.AppendLine($"  \"{FuncName(fn.Start)}\" -> \"{FuncName(callee)}\";");
                                }

                                dot.AppendLine("}");
                                File.WriteAllText(_leCallGraphDot, dot.ToString());
                                _logger.Info($"Wrote LE call graph DOT to {_leCallGraphDot}");
                            }

                            if (!string.IsNullOrWhiteSpace(_leCallGraphJson))
                            {
                                var payload = LeExports.BuildCallGraphExport(analysis);

                                var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                                {
                                    WriteIndented = true,
                                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                                });

                                File.WriteAllText(_leCallGraphJson, json);
                                _logger.Info($"Wrote LE call graph JSON to {_leCallGraphJson}");
                            }
                        }
                    }

                    if (wantLeCfgDot)
                    {
                        var analysis = LEDisassembler.GetLastAnalysis();
                        if (analysis == null || analysis.CfgByFunction == null || analysis.CfgByFunction.Count == 0)
                        {
                            _logger.Warn("Warning: -LECFGDOT requested but no LE CFG snapshot was captured (requires -LEINSIGHTS and a run that decodes relative branches)");
                        }
                        else
                        {
                            static bool TryParseHexAddr(string s, out uint addr)
                            {
                                addr = 0;
                                if (string.IsNullOrWhiteSpace(s))
                                    return false;
                                var t = s.Trim();
                                if (t.StartsWith("func_", StringComparison.OrdinalIgnoreCase))
                                    t = t.Substring("func_".Length);
                                if (t.StartsWith("bb_", StringComparison.OrdinalIgnoreCase))
                                    t = t.Substring("bb_".Length);
                                if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    t = t.Substring(2);
                                return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out addr);
                            }

                            static uint ResolveFunctionStart(LEDisassembler.LeAnalysis a, uint addr)
                            {
                                if (a == null || a.Functions == null || a.Functions.Count == 0)
                                    return addr;
                                if (a.Functions.ContainsKey(addr))
                                    return addr;
                                var starts = a.Functions.Keys.OrderBy(x => x).ToArray();
                                var idx = Array.BinarySearch(starts, addr);
                                if (idx >= 0)
                                    return starts[idx];
                                idx = ~idx - 1;
                                if (idx < 0)
                                    return starts[0];
                                return starts[idx];
                            }

                            var targetFunc = analysis.EntryLinear;
                            if (!string.IsNullOrWhiteSpace(_leOnlyFunction) && TryParseHexAddr(_leOnlyFunction, out var parsed))
                                targetFunc = parsed;
                            else if (!string.IsNullOrWhiteSpace(_leOnlyFunction))
                                _logger.Warn("Warning: -LEFUNC could not be parsed as hex; defaulting CFG export to entry function");

                            targetFunc = ResolveFunctionStart(analysis, targetFunc);

                            if (!analysis.CfgByFunction.TryGetValue(targetFunc, out var cfg) || cfg == null || cfg.Blocks == null || cfg.Blocks.Count == 0)
                            {
                                _logger.Warn($"Warning: -LECFGDOT: no CFG blocks found for func_0x{targetFunc:X8} (try -LEINSIGHTS + larger decode window)");
                            }
                            else
                            {
                                string BbName(uint a2) => $"bb_{a2:X8}";
                                string FuncName(uint a2) => $"func_{a2:X8}";

                                var dot = new StringBuilder();
                                dot.AppendLine("digraph le_cfg {");
                                dot.AppendLine("  rankdir=TB;");
                                dot.AppendLine("  node [shape=box,fontname=\"monospace\"]; ");

                                dot.AppendLine($"  subgraph cluster_{FuncName(targetFunc)} {{");
                                dot.AppendLine($"    label=\"{FuncName(targetFunc)}\";");
                                dot.AppendLine("    color=gray;");

                                foreach (var b in cfg.Blocks.Values.OrderBy(b => b.Start))
                                {
                                    var shape = b.Start == targetFunc ? "doubleoctagon" : "box";
                                    dot.AppendLine($"    \"{BbName(b.Start)}\" [shape={shape},label=\"{BbName(b.Start)}\"]; ");
                                }

                                foreach (var b in cfg.Blocks.Values.OrderBy(b => b.Start))
                                {
                                    if (b.Successors == null) continue;
                                    foreach (var succ in b.Successors.OrderBy(x => x))
                                    {
                                        if (!cfg.Blocks.ContainsKey(succ))
                                            continue;
                                        dot.AppendLine($"    \"{BbName(b.Start)}\" -> \"{BbName(succ)}\";");
                                    }
                                }

                                dot.AppendLine("  }");
                                dot.AppendLine("}");

                                File.WriteAllText(_leCfgDot, dot.ToString());
                                _logger.Info($"Wrote LE CFG DOT to {_leCfgDot} (function {FuncName(targetFunc)})");
                            }
                        }
                    }

                    if (wantLeCfgAllDot)
                    {
                        var analysis = LEDisassembler.GetLastAnalysis();
                        if (analysis == null || analysis.CfgByFunction == null || analysis.CfgByFunction.Count == 0)
                        {
                            _logger.Warn("Warning: -LECFGALLDOT requested but no LE CFG snapshot was captured (requires -LEINSIGHTS and a run that decodes relative branches)");
                        }
                        else
                        {
                            string BbName(uint a2) => $"bb_{a2:X8}";
                            string FuncName(uint a2) => $"func_{a2:X8}";

                            var dot = new StringBuilder();
                            dot.AppendLine("digraph le_cfg_all {");
                            dot.AppendLine("  rankdir=TB;");
                            dot.AppendLine("  compound=true;");
                            dot.AppendLine("  node [shape=box,fontname=\"monospace\"]; ");

                            foreach (var kv in analysis.CfgByFunction.OrderBy(k => k.Key))
                            {
                                var fStart = kv.Key;
                                var cfg = kv.Value;
                                if (cfg == null || cfg.Blocks == null || cfg.Blocks.Count == 0)
                                    continue;

                                analysis.Functions.TryGetValue(fStart, out var fInfo);
                                var ins = fInfo?.InstructionCount ?? 0;
                                var bbCount = cfg.Blocks.Count;

                                var clusterName = $"cluster_{FuncName(fStart)}";
                                dot.AppendLine($"  subgraph {clusterName} {{");
                                var entryTag = (analysis.EntryLinear == fStart) ? " (entry)" : string.Empty;
                                dot.AppendLine($"    label=\"{FuncName(fStart)}{entryTag}\\nins={ins} bb={bbCount}\";");
                                dot.AppendLine("    color=gray;");

                                foreach (var b in cfg.Blocks.Values.OrderBy(b => b.Start))
                                {
                                    var shape = b.Start == fStart ? "doubleoctagon" : "box";
                                    dot.AppendLine($"    \"{BbName(b.Start)}\" [shape={shape},label=\"{BbName(b.Start)}\"]; ");
                                }

                                foreach (var b in cfg.Blocks.Values.OrderBy(b => b.Start))
                                {
                                    if (b.Successors == null) continue;
                                    foreach (var succ in b.Successors.OrderBy(x => x))
                                    {
                                        if (!cfg.Blocks.ContainsKey(succ))
                                            continue;
                                        dot.AppendLine($"    \"{BbName(b.Start)}\" -> \"{BbName(succ)}\";");
                                    }
                                }

                                dot.AppendLine("  }");
                            }

                            dot.AppendLine("}");

                            File.WriteAllText(_leCfgAllDot, dot.ToString());
                            _logger.Info($"Wrote whole-program LE CFG DOT to {_leCfgAllDot} (functions {analysis.CfgByFunction.Count})");
                        }
                    }

                    if (wantLeCfgAllJson)
                    {
                        var analysis = LEDisassembler.GetLastAnalysis();
                        if (analysis == null || analysis.CfgByFunction == null || analysis.CfgByFunction.Count == 0)
                        {
                            _logger.Warn("Warning: -LECFGALLJSON requested but no LE CFG snapshot was captured (requires -LEINSIGHTS and a run that decodes relative branches)");
                        }
                        else
                        {
                            static string Hex(uint a2) => $"0x{a2:X8}";
                            static string FuncName(uint a2) => $"func_{a2:X8}";

                            var functions = analysis.CfgByFunction
                                .OrderBy(k => k.Key)
                                .Select(kv =>
                                {
                                    var fStart = kv.Key;
                                    var cfg = kv.Value;

                                    LEDisassembler.LeFunctionInfo fInfo = null;
                                    if (analysis.Functions != null)
                                        analysis.Functions.TryGetValue(fStart, out fInfo);
                                    var ins = fInfo?.InstructionCount ?? 0;

                                    IEnumerable<LEDisassembler.LeBasicBlockInfo> blockValues =
                                        cfg?.Blocks != null ? cfg.Blocks.Values : Enumerable.Empty<LEDisassembler.LeBasicBlockInfo>();

                                    var blocks = blockValues
                                        .OrderBy(b => b.Start)
                                        .Select(b => new
                                        {
                                            start = Hex(b.Start),
                                            predecessors = (b.Predecessors ?? new List<uint>()).OrderBy(x => x).Select(Hex).ToArray(),
                                            successors = (b.Successors ?? new List<uint>()).OrderBy(x => x).Select(Hex).ToArray(),
                                        })
                                        .ToArray();

                                    return new
                                    {
                                        start = Hex(fStart),
                                        name = FuncName(fStart),
                                        isEntry = analysis.EntryLinear == fStart ? (bool?)true : null,
                                        instructionCount = ins > 0 ? (int?)ins : null,
                                        basicBlockCount = (cfg?.Blocks?.Count ?? 0) > 0 ? (int?)cfg.Blocks.Count : null,
                                        blocks = blocks.Length > 0 ? blocks : null
                                    };
                                })
                                .ToArray();

                            var payload = new
                            {
                                input = analysis.InputFile,
                                entry = Hex(analysis.EntryLinear),
                                entryName = FuncName(analysis.EntryLinear),
                                functions
                            };

                            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                            {
                                WriteIndented = true,
                                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                            });

                            File.WriteAllText(_leCfgAllJson, json);
                            _logger.Info($"Wrote whole-program LE CFG JSON to {_leCfgAllJson} (functions {analysis.CfgByFunction.Count})");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(_leReportJson))
                    {
                        var analysis = LEDisassembler.GetLastAnalysis();
                        if (analysis == null)
                        {
                            _logger.Warn("Warning: -LEREPORTJSON requested but no LE analysis was captured (try enabling -LEINSIGHTS and avoid -LEDECOMPASM)");
                        }
                        else
                        {
                            // Best-effort enrich the report with header/object/import/fixup summary.
                            LEDisassembler.LeFixupTableInfo fixupTable = null;
                            string fixupTableError = null;
                            try
                            {
                                if (!LEDisassembler.TryBuildFixupTable(_sInputFile, _bLeScanMz, out fixupTable, out var fixErr))
                                    fixupTableError = string.IsNullOrWhiteSpace(fixErr) ? "LE fixup table parse failed" : fixErr;
                            }
                            catch (Exception ex)
                            {
                                fixupTableError = ex.Message;
                            }

                            var detectedFormat = DetectExeFormat(_sInputFile);
                            var payload = LeExports.BuildReportExport(analysis, fixupTable, detectedFormat, fixupTableError, includeFunctions: _bLeReportFuncs);

                            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                            {
                                WriteIndented = true,
                                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                            });

                            File.WriteAllText(_leReportJson, json);
                            _logger.Info($"Wrote LE report JSON to {_leReportJson} (functions {payload.functionCount})");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(_leFixupsJson))
                    {
                        if (string.IsNullOrWhiteSpace(_sInputFile) || !File.Exists(_sInputFile))
                        {
                            _logger.Warn("Warning: -LEFIXUPSJSON requested but no valid input file was provided");
                        }
                        else if (LEDisassembler.TryBuildFixupTable(_sInputFile, _bLeScanMz, out var table, out var fixErr))
                        {
                            var payload = LeExports.BuildFixupTableExport(table);

                            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                            {
                                WriteIndented = true,
                                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                            });

                            File.WriteAllText(_leFixupsJson, json);
                            _logger.Info($"Wrote LE fixup table JSON to {_leFixupsJson} (fixups {payload.fixupCount})");
                        }
                        else
                        {
                            _logger.Warn($"Warning: -LEFIXUPSJSON failed: {fixErr}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(_leImportsJson))
                    {
                        if (string.IsNullOrWhiteSpace(_sInputFile) || !File.Exists(_sInputFile))
                        {
                            _logger.Warn("Warning: -LEIMPORTSJSON requested but no valid input file was provided");
                        }
                        else if (LEDisassembler.TryBuildFixupTable(_sInputFile, _bLeScanMz, out var table, out var impErr))
                        {
                            var analysis = LEDisassembler.GetLastAnalysis();
                            var payload = LeExports.BuildImportMapExport(table, analysis);

                            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                            {
                                WriteIndented = true,
                                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                            });

                            File.WriteAllText(_leImportsJson, json);
                            _logger.Info($"Wrote LE imports JSON to {_leImportsJson} (modules {payload.moduleCount} procs {payload.procCount} xrefs {payload.xrefCount})");
                        }
                        else
                        {
                            _logger.Warn($"Warning: -LEIMPORTSJSON failed: {impErr}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(_leReachJson))
                    {
                        if (_bLeDecompile && !string.IsNullOrWhiteSpace(_leDecompileAsmFile))
                        {
                            // Already warned earlier: no LE decode pass / no input file to analyze.
                        }
                        else
                        {
                        var opts = new JsonSerializerOptions
                        {
                            WriteIndented = true,
                            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                        };

                        if (string.IsNullOrWhiteSpace(_sInputFile) || !File.Exists(_sInputFile))
                        {
                            var payload = new LeExports.LeReachabilityExport
                            {
                                input = _sInputFile,
                                error = "No valid input file was provided",
                                detectedFormat = DetectExeFormat(_sInputFile),
                                objectCount = 0,
                                totalInstructionCount = 0,
                                totalReachableInstructionCount = 0,
                                totalReachableByteCount = 0,
                                objects = Array.Empty<LeExports.LeReachabilityObject>()
                            };

                            File.WriteAllText(_leReachJson, JsonSerializer.Serialize(payload, opts));
                            _logger.Warn($"Warning: -LEREACHJSON requested but no valid input file was provided (wrote error JSON to {_leReachJson})");
                        }
                        else if (LEDisassembler.TryBuildReachabilityMap(_sInputFile, _bLeScanMz, out var reach, out var reachErr))
                        {
                            var payload = LeExports.BuildReachabilityExport(reach);
                            payload.detectedFormat = DetectExeFormat(_sInputFile);
                            File.WriteAllText(_leReachJson, JsonSerializer.Serialize(payload, opts));
                            _logger.Info($"Wrote LE reachability JSON to {_leReachJson} (objects {payload.objectCount} reachableIns {payload.totalReachableInstructionCount})");
                        }
                        else
                        {
                            var payload = new LeExports.LeReachabilityExport
                            {
                                input = _sInputFile,
                                error = reachErr,
                                detectedFormat = DetectExeFormat(_sInputFile),
                                objectCount = 0,
                                totalInstructionCount = 0,
                                totalReachableInstructionCount = 0,
                                totalReachableByteCount = 0,
                                objects = Array.Empty<LeExports.LeReachabilityObject>()
                            };

                            File.WriteAllText(_leReachJson, JsonSerializer.Serialize(payload, opts));
                            _logger.Warn($"Warning: -LEREACHJSON failed: {reachErr} (wrote error JSON to {_leReachJson})");
                        }
                        }
                    }

                    if (_bLeDecompile && _leChunks > 0 && leDecompFiles != null && leDecompFiles.Count > 0)
                    {
                        if (string.IsNullOrEmpty(_sOutputFile))
                            throw new Exception("Error: -LECHUNKS requires -O <out.c>");

                        var outDir = Path.GetDirectoryName(_sOutputFile);
                        if (string.IsNullOrEmpty(outDir)) outDir = ".";

                        foreach (var kvp in leDecompFiles)
                        {
                            var filePath = Path.Combine(outDir, kvp.Key);
                            _logger.Info($"{DateTime.Now} Writing translation unit to {filePath}");
                            File.WriteAllText(filePath, kvp.Value);
                        }
                        _logger.Info($"{DateTime.Now} Done! (Multi-file decompile)");
                        return;
                    }
                    if (_bAnalysis)
                        _logger.Warn("Warning: -analysis is not supported for LE inputs, ignoring");
                    if (_bStrings)
                        _logger.Warn("Warning: -strings is not supported for LE inputs, ignoring");
                    if (_bMinimal)
                        _logger.Warn("Warning: -minimal has no effect for LE inputs (LE output is always minimal)");
                    if (_bLeFull && _leBytesLimit.HasValue)
                        _logger.Warn("Warning: -lebytes is ignored when -lefull is specified");
                    if (_bLeDecompile)
                        _logger.Info("LE decompile mode enabled (best-effort pseudo-C)");
                    if (_bLeFixups)
                        _logger.Info("LE fixup annotations enabled (best-effort)");
                    if (_bLeGlobals && !_bLeFixups)
                        _logger.Warn("Warning: -leglobals works best with -lefixups (globals are derived from fixups)");
                    if (_bLeInsights && !_bLeFixups)
                        _logger.Warn("Warning: -leinsights works best with -lefixups (many xrefs/symbols are derived from fixups)");

                    if (_leRenderLimit.HasValue)
                    {
                        if (_leRenderLimit.Value == 0)
                            _logger.Info("LE render disabled (-lerenderlimit 0): insights still computed, instruction listing is skipped");
                        else
                            _logger.Info($"LE render limit enabled: {_leRenderLimit.Value} instructions/object");
                    }

                    if (_bLeInsights)
                        _logger.Info($"LE insights jobs: {_leJobs}");

                    if (_bLeFixDump)
                    {
                        if (LEDisassembler.TryDumpFixupsToString(_sInputFile, _leFixDumpMaxPages, 512, _bLeScanMz, out var dump, out var dumpErr))
                        {
                            if (string.IsNullOrEmpty(_sOutputFile))
                            {
                                _logger.Info(dump);
                            }
                            else
                            {
                                var dir = Path.GetDirectoryName(_sOutputFile) ?? string.Empty;
                                var baseName = Path.GetFileNameWithoutExtension(_sOutputFile);
                                var dumpPath = Path.Combine(dir, baseName + ".fixups.txt");
                                _logger.Info($"{DateTime.Now} Writing LE fixup dump to {dumpPath}");
                                File.WriteAllText(dumpPath, dump);
                            }
                        }
                        else
                        {
                            _logger.Warn($"Warning: -lefixdump requested but dump failed: {dumpErr}");
                        }
                    }

                    if (string.IsNullOrEmpty(_sOutputFile))
                    {
                        if (_splitKb.HasValue)
                            _logger.Warn("Warning: -splitkb requires -o, ignoring");
                        if (_bMacros)
                            leOutput = MacroDeduper.Apply(leOutput);
                        Console.WriteLine(leOutput);
                    }
                    else
                    {
                        // If we're in LE decompile mode and the user provided an output DIRECTORY,
                        // write all generated multipart files there (main.c, b*.c, blst.h, etc).
                        // This keeps the common workflow `-LEDECOMP -O <dir>` working.
                        if (_bLeDecompile
                            && leDecompFiles != null
                            && leDecompFiles.Count > 0
                            && (Directory.Exists(_sOutputFile)
                                || _sOutputFile.EndsWith(Path.DirectorySeparatorChar)
                                || _sOutputFile.EndsWith(Path.AltDirectorySeparatorChar)))
                        {
                            var outDir = _sOutputFile;
                            Directory.CreateDirectory(outDir);
                            _logger.Info($"{DateTime.Now} Writing LE decomp outputs to {outDir}");
                            foreach (var kvp in leDecompFiles)
                            {
                                var outPath = Path.Combine(outDir, kvp.Key);
                                File.WriteAllText(outPath, kvp.Value);
                            }
                            _logger.Info($"{DateTime.Now} Done!");
                            return;
                        }

                        if (_bMacros)
                            leOutput = MacroDeduper.Apply(leOutput);
                        if (_splitKb.HasValue)
                        {
                            WriteSplitFiles(_sOutputFile, leOutput, _splitKb.Value);
                        }
                        else
                        {
                            _logger.Info($"{DateTime.Now} Writing Disassembly to {_sOutputFile}");
                            File.WriteAllText(_sOutputFile, leOutput);
                        }
                    }

                    _logger.Info($"{DateTime.Now} Done!");
                    return;
                }

                // If LE mode failed but the user requested LE reachability export, still write a structured error payload.
                // This is common for non-LE inputs where we fall back to the MZ disassembler.
                if (!leOk && wantLeReachJson && !(_bLeDecompile && !string.IsNullOrWhiteSpace(_leDecompileAsmFile)))
                {
                    var opts = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                    };

                    var err = !string.IsNullOrWhiteSpace(leError) ? leError : "LE disassembly failed";
                    var payload = new LeExports.LeReachabilityExport
                    {
                        input = _sInputFile,
                        error = err,
                        detectedFormat = DetectExeFormat(_sInputFile),
                        objectCount = 0,
                        totalInstructionCount = 0,
                        totalReachableInstructionCount = 0,
                        totalReachableByteCount = 0,
                        objects = Array.Empty<LeExports.LeReachabilityObject>()
                    };

                    File.WriteAllText(_leReachJson, JsonSerializer.Serialize(payload, opts));
                    _logger.Warn($"Warning: -LEREACHJSON failed: {err} (wrote error JSON to {_leReachJson})");
                }

                if (!string.IsNullOrEmpty(leError) && leError != "LE header not found")
                {
                    throw new Exception(leError);
                }

                // DOS MZ support (best-effort): for plain MZ executables without an extended header.
                // Note: we also treat -lefull/-lebytes/-leinsights as convenient aliases for MZ mode
                // so existing command lines keep working when switching targets.
                var mzFull = _bMzFull || _bLeFull;
                var mzBytes = _mzBytesLimit ?? _leBytesLimit;
                var mzInsights = _bMzInsights || _bLeInsights || _bAnalysis;

                if (!string.IsNullOrEmpty(_mzReasmAsm) || !string.IsNullOrEmpty(_mzReasmAsmWasm) || !string.IsNullOrEmpty(_mzReasmJson))
                {
                    if (!string.IsNullOrEmpty(_mzReasmAsm) || !string.IsNullOrEmpty(_mzReasmJson))
                    {
                        if (MZDisassembler.TryExportReassembly(_sInputFile, _mzReasmAsm, _mzReasmJson, out var reasmErr))
                        {
                            if (!string.IsNullOrEmpty(_mzReasmAsm))
                                _logger.Info($"{DateTime.Now} Wrote MZ reassembly export to {_mzReasmAsm}");
                            if (!string.IsNullOrEmpty(_mzReasmJson))
                                _logger.Info($"{DateTime.Now} Wrote MZ reassembly metadata to {_mzReasmJson}");
                        }
                        else
                        {
                            throw new Exception($"Error: -MZREASM export failed: {reasmErr}");
                        }
                    }

                    if (!string.IsNullOrEmpty(_mzReasmAsmWasm))
                    {
                        if (MZDisassembler.TryExportReassembly(_sInputFile, _mzReasmAsmWasm, outJsonFile: null, wasmCompat: true, out var reasmErr))
                        {
                            _logger.Info($"{DateTime.Now} Wrote MZ reassembly export (WASM) to {_mzReasmAsmWasm}");
                        }
                        else
                        {
                            throw new Exception($"Error: -MZREASMWASM export failed: {reasmErr}");
                        }
                    }
                }
                if (MZDisassembler.TryDisassembleToString(_sInputFile, mzFull, mzBytes, mzInsights, _toolchainHint, out var mzOutput, out var mzError))
                {
                    if (_toolchainHint != EnumToolchainHint.None)
                        _logger.Info($"Toolchain hint enabled: {_toolchainHint}");

                    if (string.IsNullOrEmpty(_sOutputFile))
                    {
                        if (_splitKb.HasValue)
                            _logger.Warn("Warning: -splitkb requires -o, ignoring");
                        if (_bMacros)
                            mzOutput = MacroDeduper.Apply(mzOutput);
                        Console.WriteLine(mzOutput);
                    }
                    else
                    {
                        if (_bMacros)
                            mzOutput = MacroDeduper.Apply(mzOutput);
                        if (_splitKb.HasValue)
                        {
                            WriteSplitFiles(_sOutputFile, mzOutput, _splitKb.Value);
                        }
                        else
                        {
                            _logger.Info($"{DateTime.Now} Writing Disassembly to {_sOutputFile}");
                            File.WriteAllText(_sOutputFile, mzOutput);
                        }
                    }

                    _logger.Info($"{DateTime.Now} Done!");
                    return;
                }
                else if (!string.IsNullOrEmpty(mzError) && mzError != "MZ header not found" && mzError != "Has extended header (NE/LE/PE)")
                {
                    throw new Exception(mzError);
                }

                //Warn of Analysis not being available with minimal output
                if (_bMinimal && _bAnalysis)
                    _logger.Warn(
                        $"Warning: Analysis Mode unavailable with minimal output option, ignoring");

                _logger.Info($"Inspecting File: {_sInputFile}");

                //Perform Disassmebly
                var dasm = new Disassembler(_sInputFile);
                var inputFile = dasm.Disassemble(_bMinimal);

                //Apply Selected Analysis
                if (_bAnalysis)
                {
                    _logger.Info($"Performing Additional Analysis");
                    AdvancedAnalysis.Analyze(inputFile);
                }

                _logger.Info($"Writing Disassembly Output");

                //Build Final Output
                var renderer = new StringRenderer(inputFile);
                var output = new StringBuilder();
                output.AppendLine($"; Disassembly of {inputFile.Path}{inputFile.FileName}");
                output.AppendLine($"; Description: {inputFile.NonResidentNameTable[0].Name}");
                if (_toolchainHint != EnumToolchainHint.None)
                    output.AppendLine($"; Toolchain hint: {_toolchainHint}");
                output.AppendLine(";");

                //Render Segment Information to output
                output.Append(renderer.RenderSegmentInformation());
                output.Append(renderer.RenderEntryTable());
                output.AppendLine(";");
                output.Append(renderer.RenderDisassembly(_bAnalysis));

                //Write Strings to Output
                if (_bStrings)
                {
                    output.Append(renderer.RenderStrings());
                }

                var finalOutput = output.ToString();
                if (_bMacros)
                    finalOutput = MacroDeduper.Apply(finalOutput);

                if (string.IsNullOrEmpty(_sOutputFile))
                {
                    if (_splitKb.HasValue)
                        _logger.Warn("Warning: -splitkb requires -o, ignoring");
                    _logger.Info(finalOutput);
                }
                else
                {
                    if (_splitKb.HasValue)
                    {
                        WriteSplitFiles(_sOutputFile, finalOutput, _splitKb.Value);
                    }
                    else
                    {
                        _logger.Info($"{DateTime.Now} Writing Disassembly to {_sOutputFile}");
                        File.WriteAllText(_sOutputFile, finalOutput);
                    }
                }

                _logger.Info($"{DateTime.Now} Done!");
            }
            catch (Exception e)
            {
                _logger.Error(e);
                _logger.Error($"{DateTime.Now} Fatal Exception -- Exiting");
            }
        }

        private void WriteSplitFiles(string outputPath, string content, int splitKb)
        {
            var bytesPerFile = splitKb * 1024;
            var utf8 = Encoding.UTF8;

            if (bytesPerFile <= 0)
                throw new Exception("Error: invalid split size");

            var dir = Path.GetDirectoryName(outputPath);
            if (string.IsNullOrEmpty(dir))
                dir = Directory.GetCurrentDirectory();

            var baseName = Path.GetFileNameWithoutExtension(outputPath);
            if (string.IsNullOrEmpty(baseName))
                baseName = "output";

            var ext = Path.GetExtension(outputPath);
            if (string.IsNullOrEmpty(ext))
                ext = ".asm";

            // Normalize extension to look like an assembly-ish file by default
            if (!Regex.IsMatch(ext, "^\\.[A-Za-z0-9]+$"))
                ext = ".asm";

            // IMPORTANT: never split in the middle of a line/instruction.
            // We split on line boundaries and keep each part close to the requested size.
            var newline = content.Contains("\r\n") ? "\r\n" : "\n";
            var current = new StringBuilder();
            var currentBytes = 0;
            var partIndex = 1;

            void FlushPart()
            {
                if (current.Length == 0)
                    return;

                var partPath = Path.Combine(dir, $"{baseName}.{partIndex:000}{ext}");
                _logger.Info($"{DateTime.Now} Writing Disassembly chunk {partIndex} to {partPath}");
                File.WriteAllText(partPath, current.ToString(), utf8);
                partIndex++;
                current.Clear();
                currentBytes = 0;
            }

            using (var reader = new StringReader(content))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    // Re-add the newline that ReadLine() strips.
                    var lineWithNewline = line + newline;
                    var lineBytes = utf8.GetByteCount(lineWithNewline);

                    // If adding this line would exceed the target and we already have content, flush first.
                    if (currentBytes > 0 && currentBytes + lineBytes > bytesPerFile)
                        FlushPart();

                    current.Append(lineWithNewline);
                    currentBytes += lineBytes;

                    // If a single line exceeds the target size, we still keep it intact (never split lines).
                    if (currentBytes >= bytesPerFile)
                        FlushPart();
                }
            }

            FlushPart();
        }

        private static bool TryUnwrapBwBoundExecutable(
            string inputPath,
            string outputPath,
            out string unwrappedPath,
            out string note,
            out string error)
        {
            unwrappedPath = null;
            note = null;
            error = null;

            if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
            {
                error = "input file not found";
                return false;
            }

            byte[] bytes;
            try
            {
                bytes = File.ReadAllBytes(inputPath);
            }
            catch (Exception e)
            {
                error = $"failed to read input: {e.Message}";
                return false;
            }

            if (bytes.Length < 0x40 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
            {
                error = "not an MZ executable";
                return false;
            }

            static ushort ReadU16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
            static uint ReadU32(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

            static int ComputeMzSizeBytes(byte[] b)
            {
                var eCp = ReadU16(b, 0x04);
                var eCblp = ReadU16(b, 0x02);
                if (eCp == 0)
                    return b.Length;
                var size = (eCp - 1) * 512;
                size += (eCblp == 0) ? 512 : eCblp;
                return size;
            }

            // If the file is already a normal bound MZ+LE (LE at e_lfanew), do nothing.
            var eLfanew = bytes.Length >= 0x40 ? (int)ReadU32(bytes, 0x3C) : 0;
            if (eLfanew >= 0x40 && eLfanew + 2 < bytes.Length && bytes[eLfanew] == (byte)'L' && bytes[eLfanew + 1] == (byte)'E')
            {
                unwrappedPath = inputPath;
                note = $"-LEUNWRAP: input already appears to be a bound MZ+LE (LE header at 0x{eLfanew:X})";
                return true;
            }

            var overlayBase = ComputeMzSizeBytes(bytes);
            if (overlayBase < 0x40 || overlayBase + 4 > bytes.Length)
            {
                error = $"overlay base out of range (computed 0x{overlayBase:X})";
                return false;
            }

            // BW overlay header
            if (bytes[overlayBase] != (byte)'B' || bytes[overlayBase + 1] != (byte)'W')
            {
                error = "BW overlay header not found at MZ overlay base";
                return false;
            }

            var bwHeaderLen = (int)ReadU16(bytes, overlayBase + 2);
            if (bwHeaderLen <= 0 || bwHeaderLen > 64 * 1024 || overlayBase + bwHeaderLen > bytes.Length)
            {
                error = $"invalid BW header length 0x{bwHeaderLen:X}";
                return false;
            }

            // Heuristic: scan BW header u32 fields for a relative pointer to an embedded MZ which itself is bound to LE.
            var foundInnerMzOff = -1;
            var foundInnerLeOff = -1;
            for (var fieldOff = 0; fieldOff + 4 <= bwHeaderLen; fieldOff += 4)
            {
                var rel = (int)ReadU32(bytes, overlayBase + fieldOff);
                if (rel <= 0)
                    continue;
                var innerMzOff = overlayBase + rel;
                if (innerMzOff < 0 || innerMzOff + 0x40 > bytes.Length)
                    continue;
                if (bytes[innerMzOff] != (byte)'M' || bytes[innerMzOff + 1] != (byte)'Z')
                    continue;

                var innerLfanew = (int)ReadU32(bytes, innerMzOff + 0x3C);
                var innerLeOff = innerMzOff + innerLfanew;
                if (innerLfanew >= 0x40 && innerLeOff + 2 < bytes.Length && bytes[innerLeOff] == (byte)'L' && bytes[innerLeOff + 1] == (byte)'E')
                {
                    foundInnerMzOff = innerMzOff;
                    foundInnerLeOff = innerLeOff;
                    break;
                }
            }

            if (foundInnerMzOff < 0)
            {
                error = "BW header present, but no embedded bound MZ+LE was found";
                return false;
            }

            var outDir = !string.IsNullOrWhiteSpace(outputPath) ? Path.GetDirectoryName(outputPath) : Path.GetDirectoryName(inputPath);
            if (string.IsNullOrWhiteSpace(outDir))
                outDir = Directory.GetCurrentDirectory();
            Directory.CreateDirectory(outDir);

            var baseName = Path.GetFileNameWithoutExtension(inputPath);
            if (string.IsNullOrWhiteSpace(baseName))
                baseName = "unwrapped";
            unwrappedPath = Path.Combine(outDir, baseName + ".unwrapped.exe");

            try
            {
                // We write from the embedded bound EXE start to the end of the file.
                // This is sufficient for DOS extenders that keep the protected-mode payload in the appended region.
                File.WriteAllBytes(unwrappedPath, bytes.Skip(foundInnerMzOff).ToArray());
            }
            catch (Exception e)
            {
                error = $"failed to write unwrapped file: {e.Message}";
                unwrappedPath = null;
                return false;
            }

            note = $"-LEUNWRAP: BW overlay at 0x{overlayBase:X} (len 0x{bwHeaderLen:X}) -> embedded bound EXE at 0x{foundInnerMzOff:X} (LE at 0x{foundInnerLeOff:X}); wrote {unwrappedPath}";
            return true;
        }
    }
}