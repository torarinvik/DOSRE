using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using MBBSDASM.Analysis;
using MBBSDASM.Dasm;
using MBBSDASM.Enums;
using MBBSDASM.Logging;
using MBBSDASM.Renderer.impl;
using NLog;

namespace MBBSDASM.UI.impl
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
        ///     Output slicing (KB)
        ///     Specified with the -splitkb <n> argument
        ///     When used with -o, splits output into multiple numbered files about n KB each.
        /// </summary>
        private int? _splitKb;

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

                for (var i = 0; i < _args.Length; i++)
                {
                    switch (_args[i].ToUpper())
                    {
                        case "-I":
                            _sInputFile = _args[i + 1];
                            i++;
                            break;
                        case "-O":
                            _sOutputFile = _args[i + 1];
                            i++;
                            break;
                        case "-MINIMAL":
                            _bMinimal = true;
                            break;
                        case "-ANALYSIS":
                            _bAnalysis = true;
                            break;
                        case "-STRINGS":
                            _bStrings = true;
                            break;
                        case "-DOSVER":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -DOSVER requires a value (example: 6.22)");
                            _dosVersion = _args[i + 1];
                            i++;
                            break;
                        case "-LEFULL":
                            _bLeFull = true;
                            break;
                        case "-LEBYTES":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -LEBYTES requires a value");
                            if (!int.TryParse(_args[i + 1], out var bytesLimit) || bytesLimit <= 0)
                                throw new Exception("Error: -LEBYTES must be a positive integer");
                            _leBytesLimit = bytesLimit;
                            i++;
                            break;
                        case "-LEFIXUPS":
                            _bLeFixups = true;
                            break;
                        case "-LEGLOBALS":
                            _bLeGlobals = true;
                            break;
                        case "-LEINSIGHTS":
                            _bLeInsights = true;
                            break;
                        case "-LEFIXDUMP":
                            _bLeFixDump = true;
                            if (i + 1 < _args.Length && int.TryParse(_args[i + 1], out var maxPages) && maxPages > 0)
                            {
                                _leFixDumpMaxPages = maxPages;
                                i++;
                            }
                            break;
                        case "-MZFULL":
                            _bMzFull = true;
                            break;
                        case "-MZBYTES":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -MZBYTES requires a value");
                            if (!int.TryParse(_args[i + 1], out var mzBytesLimit) || mzBytesLimit <= 0)
                                throw new Exception("Error: -MZBYTES must be a positive integer");
                            _mzBytesLimit = mzBytesLimit;
                            i++;
                            break;
                        case "-MZINSIGHTS":
                            _bMzInsights = true;
                            break;
                        case "-SPLITKB":
                            if (i + 1 >= _args.Length)
                                throw new Exception("Error: -SPLITKB requires a value");
                            if (!int.TryParse(_args[i + 1], out var splitKb) || splitKb <= 0)
                                throw new Exception("Error: -SPLITKB must be a positive integer");
                            _splitKb = splitKb;
                            i++;
                            break;
                        case "-MACROS":
                            _bMacros = true;
                            break;
                        case "-?":
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
                                "-LEFIXDUMP [maxPages] -- (LE inputs) Dump raw fixup pages + decoding hints (writes <out>.fixups.txt if -O is used)");
                            Console.WriteLine(
                                "-MZFULL -- (MZ inputs) Disassemble from entrypoint to end of load module");
                            Console.WriteLine(
                                "-MZBYTES <n> -- (MZ inputs) Limit disassembly to n bytes from entrypoint");
                            Console.WriteLine(
                                "-MZINSIGHTS -- (MZ inputs) Best-effort labels/xrefs/strings for 16-bit MZ binaries");
                            Console.WriteLine(
                                "-SPLITKB <n> -- (with -O) Split output into ~n KB chunks (out.001.asm, out.002.asm, ...)");
                            Console.WriteLine(
                                "-MACROS -- Replace repeated straight-line chunks with macros (best-effort, readability)");
                            return;
                    }
                }

                //Verify Input File is Valid
                if (string.IsNullOrEmpty(_sInputFile) || !File.Exists(_sInputFile))
                    throw new Exception("Error: Please specify a valid input file");

                // Apply DOS version selection globally for interrupt DB lookups.
                DosInterruptDatabase.SetCurrentDosVersionGlobal(_dosVersion);

                //LE/DOS4GW support (minimal): bypass NE-specific pipeline
                //NOTE: This tool was originally NE-only; LE support does not include relocations/import analysis.
                if (LEDisassembler.TryDisassembleToString(_sInputFile, _bLeFull, _leBytesLimit, _bLeFixups, _bLeGlobals, _bLeInsights, out var leOutput, out var leError))
                {
                    if (_bAnalysis)
                        _logger.Warn("Warning: -analysis is not supported for LE inputs, ignoring");
                    if (_bStrings)
                        _logger.Warn("Warning: -strings is not supported for LE inputs, ignoring");
                    if (_bMinimal)
                        _logger.Warn("Warning: -minimal has no effect for LE inputs (LE output is always minimal)");
                    if (_bLeFull && _leBytesLimit.HasValue)
                        _logger.Warn("Warning: -lebytes is ignored when -lefull is specified");
                    if (_bLeFixups)
                        _logger.Info("LE fixup annotations enabled (best-effort)");
                    if (_bLeGlobals && !_bLeFixups)
                        _logger.Warn("Warning: -leglobals works best with -lefixups (globals are derived from fixups)");
                    if (_bLeInsights && !_bLeFixups)
                        _logger.Warn("Warning: -leinsights works best with -lefixups (many xrefs/symbols are derived from fixups)");

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
                        _logger.Info(leOutput);
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
                var mzInsights = _bMzInsights || _bLeInsights;
                if (MZDisassembler.TryDisassembleToString(_sInputFile, mzFull, mzBytes, mzInsights, out var mzOutput, out var mzError))
                {
                    if (_bAnalysis)
                        _logger.Warn("Warning: -analysis is not supported for MZ inputs, ignoring");
                    if (_bStrings)
                        _logger.Warn("Warning: -strings is not supported for MZ inputs (use -mzinsights for string scan), ignoring");
                    if (_bMinimal)
                        _logger.Warn("Warning: -minimal has no effect for MZ inputs (MZ output is always minimal)");

                    if (string.IsNullOrEmpty(_sOutputFile))
                    {
                        if (_splitKb.HasValue)
                            _logger.Warn("Warning: -splitkb requires -o, ignoring");
                        if (_bMacros)
                            mzOutput = MacroDeduper.Apply(mzOutput);
                        _logger.Info(mzOutput);
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
    }
}