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
        ///     Toolchain hint (best-effort heuristics)
        ///     Specified with -borland or -watcom
        /// </summary>
        private EnumToolchainHint _toolchainHint = EnumToolchainHint.None;

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
                                "-LEREPORTJSON <file.json> -- (LE inputs) Export a compact LE analysis report (counts + entry + input) in JSON format (implies -LEINSIGHTS)");
                            Console.WriteLine(
                                "-MZFULL -- (MZ inputs) Disassemble from entrypoint to end of load module");
                            Console.WriteLine(
                                "-MZBYTES <n> -- (MZ inputs) Limit disassembly to n bytes from entrypoint");
                            Console.WriteLine(
                                "-MZINSIGHTS -- (MZ inputs) Best-effort labels/xrefs/strings for 16-bit MZ binaries");
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
                var leInsightsForRun = _bLeInsights || wantLeCallGraph || wantLeCfgDot || wantLeCfgAllDot || wantLeCfgAllJson || wantLeReportJson;

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
                        leOk = LEDisassembler.TryDisassembleToString(_sInputFile, _bLeFull, _leBytesLimit, _leRenderLimit, _leJobs, _bLeFixups, _bLeGlobals, leInsightsForRun, _toolchainHint, _leStartLinear, out leOutput, out leError);
                    }
                }

                if (leOk)
                {
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
                            var payload = LeExports.BuildReportExport(analysis);

                            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
                            {
                                WriteIndented = true,
                                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                            });

                            File.WriteAllText(_leReportJson, json);
                            _logger.Info($"Wrote LE report JSON to {_leReportJson} (functions {payload.functionCount})");
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
                        if (LEDisassembler.TryDumpFixupsToString(_sInputFile, _leFixDumpMaxPages, 512, out var dump, out var dumpErr))
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
                else if (!string.IsNullOrEmpty(leError) && leError != "LE header not found")
                {
                    throw new Exception(leError);
                }

                // DOS MZ support (best-effort): for plain MZ executables without an extended header.
                // Note: we also treat -lefull/-lebytes/-leinsights as convenient aliases for MZ mode
                // so existing command lines keep working when switching targets.
                var mzFull = _bMzFull || _bLeFull;
                var mzBytes = _mzBytesLimit ?? _leBytesLimit;
                var mzInsights = _bMzInsights || _bLeInsights || _bAnalysis;
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