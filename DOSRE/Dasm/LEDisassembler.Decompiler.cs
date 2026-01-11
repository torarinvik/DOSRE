using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Enums;

using System.Security.Cryptography;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        public static bool TryDecompileToString(
            string inputFile,
            bool leFull,
            int? leBytesLimit,
            bool leFixups,
            bool leGlobals,
            bool leInsights,
            EnumToolchainHint toolchainHint,
            out string output,
            out string error)
        {
            return TryDecompileToMultipart(inputFile, leFull, leBytesLimit, leFixups, leGlobals, leInsights, toolchainHint, 0, out var files, out error)
                ? (files.TryGetValue("blst.c", out output) || (output = files.Values.FirstOrDefault()) != null)
                : (output = string.Empty) == string.Empty && false;
        }

        public static bool TryDecompileToMultipart(
            string inputFile,
            bool leFull,
            int? leBytesLimit,
            bool leFixups,
            bool leGlobals,
            bool leInsights,
            EnumToolchainHint toolchainHint,
            int chunkSize,
            out Dictionary<string, string> files,
            out string error)
        {
            return TryDecompileToMultipart(inputFile, leFull, leBytesLimit, leFixups, leGlobals, leInsights, toolchainHint, chunkSize, chunkSizeIsCount: false, out files, out error);
        }

        public static bool TryDecompileToMultipart(
            string inputFile,
            bool leFull,
            int? leBytesLimit,
            bool leFixups,
            bool leGlobals,
            bool leInsights,
            EnumToolchainHint toolchainHint,
            int chunkSize,
            bool chunkSizeIsCount,
            out Dictionary<string, string> files,
            out string error)
        {
            files = new Dictionary<string, string>();
            error = string.Empty;

            var useInsights = true;
            if (!TryDisassembleToString(
                    inputFile,
                    leFull,
                    leBytesLimit,
                    leFixups,
                    leGlobals,
                    useInsights,
                    toolchainHint,
                    out var asm,
                    out error))
            {
                return false;
            }

            var (ok, resultFiles, errText) = PseudoCFromLeAsm(
                asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n'),
                onlyFunction: null,
                strictOnlyFunction: false,
                chunkSize: chunkSize,
                chunkSizeIsCount: chunkSizeIsCount,
                inputFileForLoader: inputFile);
            if (!ok)
            {
                error = errText;
                return false;
            }

            files = resultFiles;
            return true;
        }

        public static bool TryDecompileToMultipartFromAsmFile(
            string asmFile,
            string onlyFunction,
            int chunkSize,
            out Dictionary<string, string> files,
            out string error)
        {
            return TryDecompileToMultipartFromAsmFile(asmFile, onlyFunction, chunkSize, chunkSizeIsCount: false, out files, out error);
        }

        public static bool TryDecompileToMultipartFromAsmFile(
            string asmFile,
            string onlyFunction,
            int chunkSize,
            bool chunkSizeIsCount,
            out Dictionary<string, string> files,
            out string error)
        {
            files = new Dictionary<string, string>();
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(asmFile) || !File.Exists(asmFile))
            {
                error = "Invalid asm file";
                return false;
            }

            var asm = File.ReadAllText(asmFile);
            return TryDecompileToMultipartFromAsm(asm, onlyFunction, chunkSize, chunkSizeIsCount, out files, out error);
        }

        public static bool TryDecompileToMultipartFromAsm(
            string asm,
            string onlyFunction,
            int chunkSize,
            out Dictionary<string, string> files,
            out string error)
        {
            return TryDecompileToMultipartFromAsm(asm, onlyFunction, chunkSize, chunkSizeIsCount: false, out files, out error);
        }

        public static bool TryDecompileToMultipartFromAsm(
            string asm,
            string onlyFunction,
            int chunkSize,
            bool chunkSizeIsCount,
            out Dictionary<string, string> files,
            out string error)
        {
            files = new Dictionary<string, string>();
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(asm))
            {
                error = "Empty asm";
                return false;
            }

            var (ok, resultFiles, errText) = PseudoCFromLeAsm(
                asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n'),
                onlyFunction: onlyFunction,
                strictOnlyFunction: !string.IsNullOrWhiteSpace(onlyFunction),
                chunkSize: chunkSize,
                chunkSizeIsCount: chunkSizeIsCount,
                inputFileForLoader: null);
            if (!ok)
            {
                error = errText;
                return false;
            }

            files = resultFiles;
            return true;
        }

        private static (bool ok, string output, string error) PseudoCFromLeAsm(string asm, string onlyFunction = null, bool strictOnlyFunction = false, int chunkSize = 0, bool chunkSizeIsCount = false, string inputFileForLoader = null)
        {
            if (string.IsNullOrWhiteSpace(asm))
                return (true, string.Empty, string.Empty);

            var lines = asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');

            var (ok, files, err) = PseudoCFromLeAsm(lines, onlyFunction, strictOnlyFunction: strictOnlyFunction, chunkSize: chunkSize, chunkSizeIsCount: chunkSizeIsCount, inputFileForLoader: inputFileForLoader);
            if (!ok) return (false, string.Empty, err);

            // If we have multiple files but the caller only wanted a string, join them or return the main one.
            // For now, if chunkSize was 0, it should have only one file "blst.c".
            if (files.ContainsKey("blst.c")) return (true, files["blst.c"], string.Empty);
            if (files.Count > 0) return (true, files.Values.First(), string.Empty);

            return (true, string.Empty, string.Empty);
        }

        public static (bool ok, Dictionary<string, string> files, string error) PseudoCMultiPartFromLeAsm(string asm, int chunkSize = 200)
        {
            if (string.IsNullOrWhiteSpace(asm))
                return (true, new Dictionary<string, string>(), string.Empty);

            var lines = asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
            return PseudoCFromLeAsm(lines, null, strictOnlyFunction: false, chunkSize: chunkSize, chunkSizeIsCount: false, inputFileForLoader: null);
        }

        private static (bool ok, Dictionary<string, string> files, string error) PseudoCFromLeAsm(string[] lines, string onlyFunction = null, bool strictOnlyFunction = false, int chunkSize = 0, bool chunkSizeIsCount = false, string inputFileForLoader = null)
        {
            if (chunkSize <= 0 && !strictOnlyFunction) chunkSize = 200;

            if (strictOnlyFunction && !string.IsNullOrWhiteSpace(onlyFunction))
            {
                var slice = TrySliceToSingleFunction(lines, onlyFunction);
                if (!slice.ok)
                    return (false, new Dictionary<string, string>(), slice.error);
                lines = slice.lines;
            }

            var files = new Dictionary<string, string>();
            var labelByAddr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var functions = new List<ParsedFunction>();
            var otherFunctions = new Dictionary<string, (string proto, int argCount)>(StringComparer.OrdinalIgnoreCase);
            uint? entryLinear = null;

            // Optional: if we have the original input file path, parse its LE metadata so generated
            // main.c can load the original image into guest linear memory and initialize esp.
            LEHeader leHeader = default;
            List<LEObject> leObjects = null;
            uint[] lePageMap = null;
            bool haveLeMeta = false;
            string leOrigFilename = null;
            uint leDataPagesBase = 0;
            uint leEntryEspLinear = 0;
            uint leEntryEipLinear = 0;
            uint leSuggestedMemSize = 0;

            if (!string.IsNullOrWhiteSpace(inputFileForLoader) && File.Exists(inputFileForLoader))
            {
                try
                {
                    var fileBytes = File.ReadAllBytes(inputFileForLoader);
                    if (TryFindLEHeaderOffset(fileBytes, out var headerOffset) && TryParseHeader(fileBytes, headerOffset, out leHeader, out var _))
                    {
                        leObjects = ParseObjects(fileBytes, leHeader);
                        lePageMap = ParseObjectPageMap(fileBytes, leHeader);
                        if (leObjects != null && leObjects.Count > 0 && lePageMap != null && lePageMap.Length > 0)
                        {
                            leOrigFilename = Path.GetFileName(inputFileForLoader);
                            // Data pages base (file offset): prefer the LE header field, but fall back to a packed-at-EOF
                            // heuristic when the header is stale (commonly seen in "unwrapped" executables).
                            leDataPagesBase = (uint)(leHeader.HeaderOffset + (int)leHeader.DataPagesOffset);

                            var pageSize = (ulong)leHeader.PageSize;
                            var numPages = (ulong)leHeader.NumberOfPages;
                            var lastPageSize = (ulong)leHeader.LastPageSize;
                            if (lastPageSize == 0 && pageSize != 0)
                                lastPageSize = pageSize;

                            var dataSize = 0UL;
                            if (pageSize != 0 && numPages != 0)
                                dataSize = ((numPages - 1) * pageSize) + lastPageSize;

                            if (dataSize != 0)
                            {
                                var expectedEnd = (ulong)leDataPagesBase + dataSize;
                                if (leDataPagesBase >= fileBytes.Length || expectedEnd > (ulong)fileBytes.Length)
                                {
                                    // If data pages are laid out contiguously at the end of the file, we can recover the base.
                                    if (dataSize < (ulong)fileBytes.Length)
                                    {
                                        var packedBase = (ulong)fileBytes.Length - dataSize;
                                        if (packedBase < (ulong)fileBytes.Length)
                                            leDataPagesBase = (uint)packedBase;
                                    }
                                }
                            }

                            // Entry EIP/ESP linear (best-effort).
                            var eipObj = leObjects.FirstOrDefault(o => o.Index == (int)leHeader.EntryEipObject);
                            var espObj = leObjects.FirstOrDefault(o => o.Index == (int)leHeader.EntryEspObject);
                            if (eipObj.Index != 0)
                                leEntryEipLinear = unchecked(eipObj.BaseAddress + leHeader.EntryEip);
                            if (espObj.Index != 0)
                                leEntryEspLinear = unchecked(espObj.BaseAddress + leHeader.EntryEsp);

                            // Guest memory window: cover the highest object end + slack.
                            ulong maxEnd = 0;
                            foreach (var o in leObjects)
                            {
                                var backed = unchecked(o.PageCount * leHeader.PageSize);
                                var span = Math.Max(o.VirtualSize, backed);
                                var end = (ulong)unchecked(o.BaseAddress + span);
                                if (end > maxEnd) maxEnd = end;
                            }
                            var withSlack = maxEnd + 0x10000u;
                            leSuggestedMemSize = (uint)((withSlack + 0xFFFu) & ~0xFFFu);
                            if (leSuggestedMemSize < 0x200000u) leSuggestedMemSize = 0x200000u;

                            haveLeMeta = leEntryEipLinear != 0 && leEntryEspLinear != 0 && leSuggestedMemSize != 0;
                        }
                    }
                }
                catch
                {
                    // best-effort only
                }
            }
            _addrToString.Clear();
            _addrToStringLiteral.Clear();
            _addrToGlobal.Clear();
            _addrToFuncName.Clear();
            _addrToCallDecoration.Clear();

            // Pass 1: collect labels (func_/bb_/loc_), strings, globals, and STRCALLs
            string currentLineAddrStr = null;
            foreach (var raw in lines)
            {
                var t = raw.Trim();
                if (string.IsNullOrWhiteSpace(t)) continue;

                if (!entryLinear.HasValue)
                {
                    var mEntry = Regex.Match(t, @"^;\s*Entry:\s*Obj\s+\d+\s*\+\s*0x[0-9A-Fa-f]+\s*\(Linear\s+0x(?<lin>[0-9A-Fa-f]+)\)\s*$", RegexOptions.IgnoreCase);
                    if (mEntry.Success)
                    {
                        var linStr = mEntry.Groups["lin"].Value;
                        if (uint.TryParse(linStr, System.Globalization.NumberStyles.HexNumber, null, out var lin))
                            entryLinear = lin;
                    }
                }

                var addrMatch = Regex.Match(t, @"^(?<addr>[0-9A-Fa-f]{8})h\s+");
                if (addrMatch.Success)
                {
                    currentLineAddrStr = addrMatch.Groups["addr"].Value.ToUpperInvariant();
                }

                if (currentLineAddrStr != null)
                {
                    var strCallMatch = Regex.Match(t, @"STRCALL:\s+text=[ps]_[0-9A-Fa-f]+\s+args~\d+\s+""(?<str>.*)""");
                    if (strCallMatch.Success)
                    {
                        _addrToCallDecoration[currentLineAddrStr] = strCallMatch.Groups["str"].Value;
                    }
                }

                var mLabel = Regex.Match(t, @"^(?<kind>func|bb|loc)_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                if (mLabel.Success)
                {
                    var addr = mLabel.Groups["addr"].Value.ToUpperInvariant();
                    labelByAddr[addr] = $"{mLabel.Groups["kind"].Value}_{addr}";
                    if (mLabel.Groups["kind"].Value == "func") _addrToFuncName[addr] = labelByAddr[addr];
                    continue;
                }

                // Strings: s_000C00A2 EQU 0x000C00A2 ; "users.ini"
                if (t.Contains("EQU") && t.Contains(";"))
                {
                    var mStr = Regex.Match(t, @"(?<sym>[ps]_(?<addr>[0-9A-Fa-f]{8}))\s+EQU\s+0x\k<addr>\s+;\s+""(?<str>.*)""");
                    if (mStr.Success)
                    {
                        var addr = mStr.Groups["addr"].Value.ToUpperInvariant();
                        var sym = mStr.Groups["sym"].Value;
                        var lit = mStr.Groups["str"].Value;
                        // Escape for C string literal.
                        lit = lit.Replace("\\", "\\\\").Replace("\"", "\\\"");
                        _addrToString[addr] = sym;
                        _addrToStringLiteral[addr] = "\"" + lit + "\"";
                        continue;
                    }
                }
                
                // Globals in hints or code: [0x0000AC34]
                foreach (Match mHintGlob in Regex.Matches(t, @"\[0x(?<addr>[0-9A-Fa-f]{1,8})\]"))
                {
                    var addr = mHintGlob.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                    if (!_addrToGlobal.ContainsKey(addr))
                        _addrToGlobal[addr] = $"g_{addr}";
                }

                // Globals also in SUMMARY or other comments
                foreach (Match mGlobAlt in Regex.Matches(t, @"\b(g_|ptr_)(?<addr>[0-9A-Fa-f]{8})\b"))
                {
                     var addr = mGlobAlt.Groups["addr"].Value.ToUpperInvariant();
                     _addrToGlobal[addr] = $"g_{addr}";
                }
            }
            if (_addrToString.Count > 0 || _addrToGlobal.Count > 0 || _addrToFuncName.Count > 0)
                Console.Error.WriteLine($"[DECOMP] Found {_addrToString.Count} strings, {_addrToGlobal.Count} globals and {_addrToFuncName.Count} functions.");

            // Pass 2: parse functions and instructions
            ParsedFunction currentFunc = null;
            ParsedBlock currentBlock = null;

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.Trim().StartsWith(";")) continue;
                var t = line.TrimEnd();

                var funcHdr = Regex.Match(t.Trim(), @"^func_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                if (funcHdr.Success)
                {
                    currentFunc = new ParsedFunction
                    {
                        Name = $"func_{funcHdr.Groups["addr"].Value.ToUpperInvariant()}",
                        HeaderComments = new List<string>(),
                        Blocks = new List<ParsedBlock>()
                    };
                    functions.Add(currentFunc);
                    currentBlock = null;
                    continue;
                }

                if (currentFunc != null)
                {
                    // Collect header comment lines (PROTO/CC/etc) until first instruction or label.
                    if (t.StartsWith(";", StringComparison.Ordinal) && currentBlock == null)
                    {
                        currentFunc.HeaderComments.Add(t.Trim());
                        continue;
                    }

                    var blockHdr = Regex.Match(t.Trim(), @"^(?<kind>bb|loc)_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                    if (blockHdr.Success)
                    {
                        currentBlock = new ParsedBlock
                        {
                            Label = $"{blockHdr.Groups["kind"].Value}_{blockHdr.Groups["addr"].Value.ToUpperInvariant()}",
                            Lines = new List<ParsedInsOrComment>()
                        };
                        currentFunc.Blocks.Add(currentBlock);
                        continue;
                    }

                    // Instruction line: 0007E060h 56  push esi
                    var ins = TryParseAsmInstructionLine(t);
                    if (ins != null)
                    {
                        if (currentBlock == null)
                        {
                            // Some functions begin with straight instructions before any bb_/loc_ labels.
                            currentBlock = new ParsedBlock { Label = currentFunc.Name, Lines = new List<ParsedInsOrComment>() };
                            currentFunc.Blocks.Add(currentBlock);
                        }

                        currentBlock.Lines.Add(ins);
                        continue;
                    }

                    // Preserve non-empty comment lines inside the function.
                    if (!string.IsNullOrWhiteSpace(t) && currentBlock != null && t.TrimStart().StartsWith(";", StringComparison.Ordinal))
                    {
                        currentBlock.Lines.Add(new ParsedInsOrComment { Kind = ParsedLineKind.Comment, Raw = t.Trim() });
                    }
                }
            }

            foreach (var fn in functions)
            {
                BuildCFG(fn, labelByAddr);
                InferVariableTypes(fn);
                MarkLoopHeaders(fn, labelByAddr);
                
                // Cross-block state propagation
                var blockEntryStates = new Dictionary<string, DecompilationState>(StringComparer.OrdinalIgnoreCase);
                if (fn.Blocks.Count > 0)
                {
                    var startBlock = fn.Blocks[0];
                    blockEntryStates[startBlock.Label] = new DecompilationState();

                    // Fixpoint worklist: keep joining states until convergence.
                    var queue = new Queue<ParsedBlock>();
                    var enqueued = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    queue.Enqueue(startBlock);
                    enqueued.Add(startBlock.Label);

                    while (queue.Count > 0)
                    {
                        var block = queue.Dequeue();
                        enqueued.Remove(block.Label);

                        if (!blockEntryStates.TryGetValue(block.Label, out var entry))
                            continue;

                        var outState = entry.Clone();
                        foreach (var line in block.Lines)
                        {
                            if (line.Kind == ParsedLineKind.Instruction)
                                SimulateInstructionForState(line, outState, fn);
                        }

                        foreach (var succLabel in block.Successors)
                        {
                            var succ = fn.Blocks.FirstOrDefault(b => b.Label.Equals(succLabel, StringComparison.OrdinalIgnoreCase));
                            if (succ == null)
                                continue;

                            if (!blockEntryStates.TryGetValue(succLabel, out var existing))
                            {
                                blockEntryStates[succLabel] = outState.Clone();
                                if (enqueued.Add(succLabel))
                                    queue.Enqueue(succ);
                                continue;
                            }

                            var merged = JoinStates(existing, outState);
                            if (!StateEquals(existing, merged))
                            {
                                blockEntryStates[succLabel] = merged;
                                if (enqueued.Add(succLabel))
                                    queue.Enqueue(succ);
                            }
                        }
                    }
                }
                fn.BlockEntryStates = blockEntryStates;

                var proto = ExtractProtoFromHeader(fn.HeaderComments);
                if (string.IsNullOrWhiteSpace(proto))
                {
                    // Basic argument inference
                    int maxArg = -1;
                    foreach (var block in fn.Blocks)
                    {
                        foreach (var line in block.Lines)
                        {
                            if (line.Kind != ParsedLineKind.Instruction) continue;
                            var matches = Regex.Matches(line.Asm, @"arg_(?<idx>[0-9A-Fa-f]+)", RegexOptions.IgnoreCase);
                            foreach (Match m in matches)
                            {
                                if (int.TryParse(m.Groups["idx"].Value, System.Globalization.NumberStyles.HexNumber, null, out var idx))
                                    if (idx >= 0 && idx < 128)
                                    {
                                        if (idx > maxArg) maxArg = idx;
                                    }
                            }
                        }
                    }
                    
                    // Also check for stdcall ret imm
                    foreach (var block in fn.Blocks)
                    {
                        var last = block.Lines.LastOrDefault(l => l.Kind == ParsedLineKind.Instruction);
                        if (last != null && last.Asm.StartsWith("ret ", StringComparison.OrdinalIgnoreCase))
                        {
                            var m = Regex.Match(last.Asm, @"ret\s+(?<off>0x[0-9A-Fa-f]+|[0-9]+|[0-9A-Fa-f]+h)", RegexOptions.IgnoreCase);
                            if (m.Success)
                            {
                                var offStr = m.Groups["off"].Value;
                                int off;
                                if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) 
                                    off = (int)Convert.ToUInt32(offStr.Substring(2), 16);
                                else if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                                    off = (int)Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                                else 
                                    off = int.Parse(offStr);
                                
                                int argsFromRet = (off / 4) - 1;
                                if (argsFromRet > maxArg) maxArg = argsFromRet;
                            }
                        }
                    }

                    var argList = new List<string>();
                    for (int j = 0; j <= maxArg; j++)
                    {
                        var varName = $"arg_{j:x}";
                        var ty = fn.InferredTypes.GetValueOrDefault(varName, "uint32_t");
                        argList.Add($"{ty} {varName}");
                    }
                    var argsStr = argList.Any() ? string.Join(", ", argList) : "";
                    
                    var retType = "uint32_t"; 
                    fn.RetType = retType;
                    fn.Proto = $"{retType} {fn.Name}({argsStr})";
                    fn.ArgCount = (maxArg >= 0) ? (maxArg + 1) : 0;
                }
                else 
                {
                    // Detect return type from custom proto
                    if (proto.StartsWith("uint32_t", StringComparison.OrdinalIgnoreCase)) fn.RetType = "uint32_t";
                    else if (proto.StartsWith("int", StringComparison.OrdinalIgnoreCase)) fn.RetType = "int";
                    else {
                        fn.RetType = "uint32_t";
                        // If it started with void, replace it.
                        if (proto.StartsWith("void", StringComparison.OrdinalIgnoreCase))
                            proto = "uint32_t" + proto.Substring(4);
                    }
                    fn.Proto = proto;
                    fn.ArgCount = Regex.Matches(proto, @"\barg_[0-9A-Fa-f]+\b").Count;
                }
            }

            // Emit pseudo-C
            var sb = new StringBuilder();
            sb.AppendLine("// DOSRE LE pseudo-decompile (best-effort)");
            sb.AppendLine("// Notes:");
            sb.AppendLine("// - This is not a full decompiler yet; it emits structured pseudo-C with gotos.");
            sb.AppendLine("// - It reuses LE insights/symbolization from the disassembler output.");
            sb.AppendLine("// - Memory operands use uint*_t; assume <stdint.h>.");
            sb.AppendLine("#include <stdint.h>");
            sb.AppendLine("#include <stddef.h>");
            sb.AppendLine("#include <string.h>");
            sb.AppendLine();
            sb.AppendLine("// Stubs for compilability");
            sb.AppendLine("#define strlen_rep(edi, al, ecx) 0 /* stub */");
            sb.AppendLine();
            sb.AppendLine("// Low-level hooks (port I/O + interrupts)");
            sb.AppendLine("// - On DOS targets (DJGPP/Watcom) we provide best-effort real implementations.");
            sb.AppendLine("// - On other hosts these are safe stubs so the file still compiles.");
            sb.AppendLine("#if defined(__WATCOMC__) && defined(__386__)");
            sb.AppendLine("#include <i86.h>");
            sb.AppendLine("// Port I/O in 32-bit Watcom (DOS4GW): implement with pragma aux.");
            sb.AppendLine("void __dos_out8(uint16_t port, uint8_t val);");
            sb.AppendLine("#pragma aux __dos_out8 = \"out dx, al\" parm [dx] [al] modify exact []");
            sb.AppendLine("uint8_t __dos_in8(uint16_t port);");
            sb.AppendLine("#pragma aux __dos_in8 = \"in al, dx\" parm [dx] value [al] modify exact []");
            sb.AppendLine("#define __out(port, val) __dos_out8((uint16_t)(port), (uint8_t)(val))");
            sb.AppendLine("#define __in(port) __dos_in8((uint16_t)(port))");
            sb.AppendLine("#elif (defined(__i386__) || defined(__x86_64__)) && (defined(__GNUC__) || defined(__clang__))");
            sb.AppendLine("static inline void __dos_out8(uint16_t port, uint8_t val) { __asm__ volatile(\"outb %0, %1\" : : \"a\"(val), \"Nd\"(port)); }");
            sb.AppendLine("static inline uint8_t __dos_in8(uint16_t port) { uint8_t ret; __asm__ volatile(\"inb %1, %0\" : \"=a\"(ret) : \"Nd\"(port)); return ret; }");
            sb.AppendLine("#define __out(port, val) __dos_out8((uint16_t)(port), (uint8_t)(val))");
            sb.AppendLine("#define __in(port) __dos_in8((uint16_t)(port))");
            sb.AppendLine("#else");
            sb.AppendLine("#define __out(port, val) ((void)(port), (void)(val))");
            sb.AppendLine("#define __in(port) (0u)");
            sb.AppendLine("#endif");
            sb.AppendLine();
            sb.AppendLine("#if defined(__DJGPP__)");
            sb.AppendLine("#include <dpmi.h>");
            sb.AppendLine("#define DOS_INT(intno) do { \\");
            sb.AppendLine("    __dpmi_regs __r; memset(&__r, 0, sizeof(__r)); \\");
            sb.AppendLine("    __r.x.eax = (unsigned long)eax; __r.x.ebx = (unsigned long)ebx; __r.x.ecx = (unsigned long)ecx; __r.x.edx = (unsigned long)edx; \\");
            sb.AppendLine("    __r.x.esi = (unsigned long)esi; __r.x.edi = (unsigned long)edi; \\");
            sb.AppendLine("    __dpmi_int((intno), &__r); \\");
            sb.AppendLine("    eax = (uint32_t)__r.x.eax; ebx = (uint32_t)__r.x.ebx; ecx = (uint32_t)__r.x.ecx; edx = (uint32_t)__r.x.edx; \\");
            sb.AppendLine("    esi = (uint32_t)__r.x.esi; edi = (uint32_t)__r.x.edi; \\");
            sb.AppendLine("} while(0)");
            sb.AppendLine("#elif defined(__WATCOMC__) && defined(__386__)");
            sb.AppendLine("#include <i86.h>");
            sb.AppendLine("#define DOS_INT(intno) do { \\");
            sb.AppendLine("    union REGS __inr, __outr; memset(&__inr, 0, sizeof(__inr)); memset(&__outr, 0, sizeof(__outr)); \\");
            sb.AppendLine("    __inr.x.eax = (unsigned long)eax; __inr.x.ebx = (unsigned long)ebx; __inr.x.ecx = (unsigned long)ecx; __inr.x.edx = (unsigned long)edx; \\");
            sb.AppendLine("    __inr.x.esi = (unsigned long)esi; __inr.x.edi = (unsigned long)edi; \\");
            sb.AppendLine("    int386((intno), &__inr, &__outr); \\");
            sb.AppendLine("    eax = (uint32_t)__outr.x.eax; ebx = (uint32_t)__outr.x.ebx; ecx = (uint32_t)__outr.x.ecx; edx = (uint32_t)__outr.x.edx; \\");
            sb.AppendLine("    esi = (uint32_t)__outr.x.esi; edi = (uint32_t)__outr.x.edi; \\");
            sb.AppendLine("} while(0)");
            sb.AppendLine("#elif defined(__WATCOMC__)");
            sb.AppendLine("#define DOS_INT(intno) do { (void)(intno); } while(0)");
            sb.AppendLine("#else");
            sb.AppendLine("#define DOS_INT(intno) do { (void)(intno); /* stub */ } while(0)");
            sb.AppendLine("#endif");
            sb.AppendLine();
            sb.AppendLine("static uint8_t* __mem; static uint32_t __mem_size;");
            sb.AppendLine("static inline void* __ptr(uint32_t addr) { return (addr < __mem_size) ? (void*)(__mem + addr) : (void*)0; }");
            sb.AppendLine();
            sb.AppendLine("// Best-effort stack pop: reads dword at esp and advances esp by 4.");
            sb.AppendLine("static inline uint32_t __pop32(uint32_t *esp_) { uint32_t v = *(uint32_t*)__ptr(*esp_); *esp_ += 4; return v; }");
            sb.AppendLine("#define pop() __pop32(&esp)");
            sb.AppendLine("#define memset_32(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*4)");
            sb.AppendLine("#define memset_16(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*2)");
            sb.AppendLine("#define __builtin_bswap32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))");
            sb.AppendLine("uint32_t func_0000000D() { return 0; }");
            sb.AppendLine("uint32_t func_000000EA() { return 0; }");
            sb.AppendLine("uint32_t func_000000FA() { return 0; }");
            sb.AppendLine("uint32_t func_00000028() { return 0; }");
            sb.AppendLine();

            // Pass: Collect all referenced functions, globals, and ptrs to ensure forward declarations
            var referencedFunctions = new HashSet<string>(functions.Select(f => f.Name), StringComparer.OrdinalIgnoreCase);
            var fieldOffsets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ptrSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var globalSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var flagSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var pseudoStringSymbols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var fn in functions)
            {
                foreach (var block in fn.Blocks)
                {
                    foreach (var line in block.Lines)
                    {
                        var text = line.Asm + " " + line.Comment + " " + line.Raw;
                        
                        // Look for calls: func_XXXXXXXX or just addresses that might be functions
                        var callMatches = Regex.Matches(text, @"\b(?<name>(?:func|loc|bb)_[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match match in callMatches)
                        {
                            var rawName = match.Groups["name"].Value;
                            var hexStr = rawName.Split('_')[1].ToUpperInvariant();
                            var name = "func_" + hexStr;
                            bool isAssigned = Regex.IsMatch(line.Asm, $@"\w+\s*=\s*{rawName}\b");

                            if (referencedFunctions.Contains(name))
                            {
                                var target = functions.First(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                                if (isAssigned && target.RetType == "void")
                                {
                                    target.RetType = "uint32_t";
                                    target.Proto = target.Proto.Replace("void " + target.Name, "uint32_t " + target.Name);
                                }
                            }
                            else
                            {
                                if (!otherFunctions.ContainsKey(name))
                                {
                                    int detectedArgs = 0;
                                    var hintMatch = Regex.Match(line.Comment ?? "", @"args~(?<cnt>\d+)");
                                    if (hintMatch.Success) int.TryParse(hintMatch.Groups["cnt"].Value, out detectedArgs);
                                    
                                    otherFunctions[name] = ($"uint32_t {name}(" + string.Join(", ", Enumerable.Repeat("uint32_t", detectedArgs).Select((t, idx) => $"{t} arg_{idx}")) + ")", detectedArgs);
                                }
                            }
                        }

                        // Collect field_XXXX offsets
                        var fieldMatches = Regex.Matches(text, @"\bfield_(?<off>[0-9A-Fa-f]+)\b", RegexOptions.IgnoreCase);
                        foreach (Match fm in fieldMatches)
                        {
                            var off = fm.Groups["off"].Value.ToLowerInvariant();
                            fieldOffsets.Add($"field_{off}");
                        }

                        // Collect ptr_XXXXXXXX symbols
                        var ptrMatches = Regex.Matches(text, @"\bptr_(?<addr>[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match pm in ptrMatches)
                        {
                            var addr = pm.Groups["addr"].Value.ToUpperInvariant();
                            ptrSymbols.Add($"ptr_{addr}");
                        }

                        // Collect g_XXXXXXXX symbols
                        var globalMatches = Regex.Matches(text, @"\bg_(?<addr>[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match gm in globalMatches)
                        {
                            var addr = gm.Groups["addr"].Value.ToUpperInvariant();
                            globalSymbols.Add($"g_{addr}");
                        }

                        // Collect flags_XXXXXXXX symbols (inferred flag storage)
                        var flagsMatches = Regex.Matches(text, @"\bflags_(?<addr>[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match fm in flagsMatches)
                        {
                            var addr = fm.Groups["addr"].Value.ToUpperInvariant();
                            flagSymbols.Add($"flags_{addr}");
                        }

                        // Collect s_/p_ symbols referenced in code. Not all of these are guaranteed to appear in the
                        // header string table; if missing, we still need a placeholder declaration for compilation.
                        var spMatches = Regex.Matches(text, @"\b(?<pre>[ps])_(?<addr>[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match sm in spMatches)
                        {
                            var pre = sm.Groups["pre"].Value.ToLowerInvariant();
                            var addr = sm.Groups["addr"].Value.ToUpperInvariant();
                            pseudoStringSymbols.Add($"{pre}_{addr}");
                        }
                    }
                }
            }

            sb.AppendLine("static uint32_t cs, ds, es, fs, gs, ss, dr0, dr1, dr2, dr3, dr6, dr7, _this, carry;");
            sb.AppendLine("static int jz, jnz, je, jne, jg, jge, jl, jle, ja, jae, jb, jbe, jo, jno, js, jns; // status flags");
            sb.AppendLine();

            var allFoundGlobals = new HashSet<string>(_addrToGlobal.Values, StringComparer.OrdinalIgnoreCase);
            allFoundGlobals.UnionWith(globalSymbols);
            allFoundGlobals.UnionWith(flagSymbols);

            var byteGlobals = new List<(uint addr, string sym)>();
            var otherGlobals = new List<string>();
            foreach (var gsym in allFoundGlobals)
            {
                var m = Regex.Match(gsym, @"^g_(?<addr>[0-9A-Fa-f]{8})$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var addr = Convert.ToUInt32(m.Groups["addr"].Value, 16);
                    byteGlobals.Add((addr, $"g_{m.Groups["addr"].Value.ToUpperInvariant()}"));
                }
                else
                {
                    otherGlobals.Add(gsym);
                }
            }

            var pages = new SortedDictionary<uint, List<(uint addr, string sym)>>();
            foreach (var bg in byteGlobals)
            {
                var baseAddr = bg.addr & 0xFFFFF000u;
                if (!pages.TryGetValue(baseAddr, out var list))
                {
                    list = new List<(uint addr, string sym)>();
                    pages[baseAddr] = list;
                }
                list.Add((bg.addr, bg.sym));
            }

            var knownStringSyms = new HashSet<string>(_addrToString.Values, StringComparer.OrdinalIgnoreCase);

            // Determine how to enter the translated program.
            // Prefer a direct function start at the LE entry; otherwise, jump to the nearest decoded instruction
            // at/after the entry address within the containing function.
            string entryDirectFunc = null;
            string entryContainerFunc = null;
            uint? entryJumpAddr = null;

            if (entryLinear.HasValue)
            {
                var entryName = $"func_{entryLinear.Value:X8}";
                if (functions.Any(f => string.Equals(f.Name, entryName, StringComparison.OrdinalIgnoreCase)))
                {
                    entryDirectFunc = entryName;
                }
                else
                {
                    ParsedFunction best = null;
                    uint bestStart = 0;
                    var entry = entryLinear.Value;

                    foreach (var fn in functions)
                    {
                        uint min = uint.MaxValue;
                        uint max = 0;
                        var any = false;
                        foreach (var b in fn.Blocks)
                        {
                            foreach (var l in b.Lines)
                            {
                                if (l.Kind != ParsedLineKind.Instruction) continue;
                                var a = (uint)l.Address;
                                any = true;
                                if (a < min) min = a;
                                if (a > max) max = a;
                            }
                        }
                        if (!any) continue;
                        if (entry < min || entry > max) continue;

                        if (best == null || min > bestStart)
                        {
                            best = fn;
                            bestStart = min;
                        }
                    }

                    if (best != null)
                    {
                        entryContainerFunc = best.Name;

                        var addrs = new List<uint>();
                        foreach (var b in best.Blocks)
                        {
                            foreach (var l in b.Lines)
                            {
                                if (l.Kind != ParsedLineKind.Instruction) continue;
                                addrs.Add((uint)l.Address);
                            }
                        }
                        addrs.Sort();

                        foreach (var a in addrs)
                        {
                            if (a >= entry)
                            {
                                entryJumpAddr = a;
                                break;
                            }
                        }
                        if (!entryJumpAddr.HasValue && addrs.Count > 0)
                            entryJumpAddr = addrs[addrs.Count - 1];
                    }
                }
            }

            if (chunkSize <= 0)
            {
                var sbSingle = new StringBuilder();
                sbSingle.AppendLine("#include <stdint.h>");
                sbSingle.AppendLine("#include <stdio.h>");
                sbSingle.AppendLine("#include <string.h>");
                sbSingle.AppendLine("#include <stdlib.h>");
                sbSingle.AppendLine();
                sbSingle.AppendLine("#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))");
                sbSingle.AppendLine("#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))");
                sbSingle.AppendLine("#define ROR8(x, n) (uint8_t)(((x) >> (n)) | ((x) << (8 - (n))))");
                sbSingle.AppendLine("#define ROL8(x, n) (uint8_t)(((x) << (n)) | ((x) >> (8 - (n))))");
                sbSingle.AppendLine("#define ROR16(x, n) (uint16_t)(((x) >> (n)) | ((x) << (16 - (n))))");
                sbSingle.AppendLine("#define ROL16(x, n) (uint16_t)(((x) << (n)) | ((x) >> (16 - (n))))");
                sbSingle.AppendLine();
                sbSingle.AppendLine("#ifdef __WATCOMC__");
                sbSingle.AppendLine("#include <conio.h>");
                sbSingle.AppendLine("void outportb(uint16_t port, uint8_t val);");
                sbSingle.AppendLine("#pragma aux outportb = \"out dx, al\" parm [dx] [al];");
                sbSingle.AppendLine("void outportw(uint16_t port, uint16_t val);");
                sbSingle.AppendLine("#pragma aux outportw = \"out dx, ax\" parm [dx] [ax];");
                sbSingle.AppendLine("void outportd(uint16_t port, uint32_t val);");
                sbSingle.AppendLine("#pragma aux outportd = \"out dx, eax\" parm [dx] [eax];");
                sbSingle.AppendLine("uint8_t inportb(uint16_t port);");
                sbSingle.AppendLine("#pragma aux inportb = \"in al, dx\" parm [dx] value [al];");
                sbSingle.AppendLine("uint16_t inportw(uint16_t port);");
                sbSingle.AppendLine("#pragma aux inportw = \"in ax, dx\" parm [dx] value [ax];");
                sbSingle.AppendLine("uint32_t inportd(uint16_t port);");
                sbSingle.AppendLine("#pragma aux inportd = \"in eax, dx\" parm [dx] value [eax];");
                sbSingle.AppendLine("#else");
                sbSingle.AppendLine("#define outportb(p,v) (void)0");
                sbSingle.AppendLine("#define inportb(p) 0");
                sbSingle.AppendLine("#endif");
                sbSingle.AppendLine();
                sbSingle.AppendLine("#if defined(__DJGPP__)");
                sbSingle.AppendLine("#include <dpmi.h>");
                sbSingle.AppendLine("#define DOS_INT(intno) do { \\");
                sbSingle.AppendLine("    __dpmi_regs __r; memset(&__r, 0, sizeof(__r)); \\");
                sbSingle.AppendLine("    __r.x.eax = (unsigned long)eax; __r.x.ebx = (unsigned long)ebx; __r.x.ecx = (unsigned long)ecx; __r.x.edx = (unsigned long)edx; \\");
                sbSingle.AppendLine("    __r.x.esi = (unsigned long)esi; __r.x.edi = (unsigned long)edi; \\");
                sbSingle.AppendLine("    __dpmi_int((intno), &__r); \\");
                sbSingle.AppendLine("    eax = (uint32_t)__r.x.eax; ebx = (uint32_t)__r.x.ebx; ecx = (uint32_t)__r.x.ecx; edx = (uint32_t)__r.x.edx; \\");
                sbSingle.AppendLine("    esi = (uint32_t)__r.x.esi; edi = (uint32_t)__r.x.edi; \\");
                sbSingle.AppendLine("} while(0)");
                sbSingle.AppendLine("#elif defined(__WATCOMC__) && defined(__386__)");
                sbSingle.AppendLine("#include <i86.h>");
                sbSingle.AppendLine("#define DOS_INT(intno) do { \\");
                sbSingle.AppendLine("    union REGS __inr, __outr; memset(&__inr, 0, sizeof(__inr)); memset(&__outr, 0, sizeof(__outr)); \\");
                sbSingle.AppendLine("    __inr.x.eax = (unsigned long)eax; __inr.x.ebx = (unsigned long)ebx; __inr.x.ecx = (unsigned long)ecx; __inr.x.edx = (unsigned long)edx; \\");
                sbSingle.AppendLine("    __inr.x.esi = (unsigned long)esi; __inr.x.edi = (unsigned long)edi; \\");
                sbSingle.AppendLine("    int386((intno), &__inr, &__outr); \\");
                sbSingle.AppendLine("    eax = (uint32_t)__outr.x.eax; ebx = (uint32_t)__outr.x.ebx; ecx = (uint32_t)__outr.x.ecx; edx = (uint32_t)__outr.x.edx; \\");
                sbSingle.AppendLine("    esi = (uint32_t)__outr.x.esi; edi = (uint32_t)__outr.x.edi; \\");
                sbSingle.AppendLine("} while(0)");
                sbSingle.AppendLine("#elif defined(__WATCOMC__)");
                sbSingle.AppendLine("#define DOS_INT(intno) do { (void)(intno); } while(0)");
                sbSingle.AppendLine("#else");
                sbSingle.AppendLine("#define DOS_INT(intno) do { (void)(intno); /* stub */ } while(0)");
                sbSingle.AppendLine("#endif");
                sbSingle.AppendLine();
                sbSingle.AppendLine("static uint8_t* __mem; static uint32_t __mem_size;");
                sbSingle.AppendLine("static inline void* __ptr(uint32_t addr) { return (addr < __mem_size) ? (void*)(__mem + addr) : (void*)0; }");
                sbSingle.AppendLine();
                sbSingle.AppendLine("// Best-effort stack pop: reads dword at guest linear esp and advances esp by 4.");
                sbSingle.AppendLine("static inline uint32_t __pop32(uint32_t *esp_) { uint32_t v = *(uint32_t*)__ptr(*esp_); *esp_ += 4; return v; }");
                sbSingle.AppendLine("#define pop() __pop32(&esp)");
                sbSingle.AppendLine("#define memset_32(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*4)");
                sbSingle.AppendLine("#define memset_16(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*2)");
                sbSingle.AppendLine("#define __builtin_bswap32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))");
                sbSingle.AppendLine("uint32_t func_0000000D() { return 0; }");
                sbSingle.AppendLine("uint32_t func_000000EA() { return 0; }");
                sbSingle.AppendLine("uint32_t func_000000FA() { return 0; }");
                sbSingle.AppendLine("uint32_t func_00000028() { return 0; }");
                sbSingle.AppendLine();

                sbSingle.AppendLine("static uint32_t cs, ds, es, fs, gs, ss, dr0, dr1, dr2, dr3, dr6, dr7, _this, carry;");
                sbSingle.AppendLine("static int jz, jnz, je, jne, jg, jge, jl, jle, ja, jae, jb, jbe, jo, jno, js, jns; // status flags");
                sbSingle.AppendLine("static uint32_t __entry_jump_enabled, __entry_jump_target, __entry_jump_addr;");
                sbSingle.AppendLine();

                foreach (var kvp in pages)
                {
                    var baseAddr = kvp.Key;
                    sbSingle.AppendLine($"static uint8_t g_page_{baseAddr:X8}[0x1000];");
                }
                if (pages.Count > 0)
                {
                    sbSingle.AppendLine("static inline uint8_t* G(uint32_t addr)");
                    sbSingle.AppendLine("{");
                    sbSingle.AppendLine("    switch (addr & 0xFFFFF000u)");
                    sbSingle.AppendLine("    {");
                    foreach (var kvp in pages)
                    {
                        var baseAddr = kvp.Key;
                        sbSingle.AppendLine($"        case 0x{baseAddr:X8}u: return &g_page_{baseAddr:X8}[addr & 0xFFFu];");
                    }
                    sbSingle.AppendLine("        default: return (uint8_t*)0;");
                    sbSingle.AppendLine("    }");
                    sbSingle.AppendLine("}");
                }

                foreach (var gsym in otherGlobals.OrderBy(x => x))
                {
                    sbSingle.AppendLine($"static uint8_t {gsym}[1];");
                }

                foreach (var kvp in _addrToString.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var addr = kvp.Key;
                    var sym = kvp.Value;
                    var lit = _addrToStringLiteral.TryGetValue(addr, out var sLit) ? sLit : "\"\"";
                    sbSingle.AppendLine($"static const char {sym}[] = {lit};");
                }

                foreach (var psym in pseudoStringSymbols.OrderBy(x => x))
                {
                    if (knownStringSyms.Contains(psym)) continue;
                    sbSingle.AppendLine($"static uint8_t {psym}[1];");
                }

                foreach (var foff in fieldOffsets.OrderBy(x => x))
                {
                    var off = foff.Substring(6);
                    sbSingle.AppendLine($"#define {foff} 0x{off}");
                }
                foreach (var psym in ptrSymbols.OrderBy(x => x))
                {
                    sbSingle.AppendLine($"static uint8_t {psym}[1];");
                    var addr = psym.Substring(4);
                    sbSingle.AppendLine($"#define M_{psym} 0x{addr}");
                }
                sbSingle.AppendLine();

                foreach (var fn in functions.OrderBy(x => x.Name))
                {
                    var p = fn.Proto.Replace("(void)", "()");
                    sbSingle.AppendLine($"{p};");
                }
                foreach (var kvp in otherFunctions.OrderBy(x => x.Key))
                {
                    sbSingle.AppendLine($"{kvp.Value.proto};");
                }
                sbSingle.AppendLine();

                var functionsByName = functions.ToDictionary(f => f.Name, f => f, StringComparer.OrdinalIgnoreCase);

                foreach (var fn in functions)
                {
                    sbSingle.Append(EmitFunctionBody(fn, labelByAddr, functionsByName, otherFunctions, entryLinear, entryContainerFunc, entryJumpAddr));
                }

                files["blst.c"] = sbSingle.ToString();
            }
            else
            {
                // Multi-file chunked output
                var h = new StringBuilder();
                h.AppendLine("#ifndef BLST_H");
                h.AppendLine("#define BLST_H");
                h.AppendLine("#include <stdint.h>");
                h.AppendLine("#include <stdio.h>");
                h.AppendLine("#include <string.h>");
                h.AppendLine("#include <stdlib.h>");
                h.AppendLine();
                h.AppendLine("#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))");
                h.AppendLine("#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))");
                h.AppendLine("#define ROR8(x, n) (uint8_t)(((x) >> (n)) | ((x) << (8 - (n))))");
                h.AppendLine("#define ROL8(x, n) (uint8_t)(((x) << (n)) | ((x) >> (8 - (n))))");
                h.AppendLine("#define ROR16(x, n) (uint16_t)(((x) >> (n)) | ((x) << (16 - (n))))");
                h.AppendLine("#define ROL16(x, n) (uint16_t)(((x) << (n)) | ((x) >> (16 - (n))))");
                h.AppendLine();
                h.AppendLine("#define __in(port) inportb((uint16_t)(port))");
                h.AppendLine("#define __out(port, val) outportb((uint16_t)(port), (uint8_t)(val))");
                h.AppendLine("#define __inw(port) inportw((uint16_t)(port))");
                h.AppendLine("#define __outw(port, val) outportw((uint16_t)(port), (uint16_t)(val))");
                h.AppendLine("#define __ind(port) inportd((uint16_t)(port))");
                h.AppendLine("#define __outd(port, val) outportd((uint16_t)(port), (uint32_t)(val))");
                h.AppendLine();
                h.AppendLine("#ifdef __WATCOMC__");
                h.AppendLine("#include <conio.h>");
                h.AppendLine("void outportb(uint16_t port, uint8_t val);");
                h.AppendLine("#pragma aux outportb = \"out dx, al\" parm [dx] [al];");
                h.AppendLine("void outportw(uint16_t port, uint16_t val);");
                h.AppendLine("#pragma aux outportw = \"out dx, ax\" parm [dx] [ax];");
                h.AppendLine("void outportd(uint16_t port, uint32_t val);");
                h.AppendLine("#pragma aux outportd = \"out dx, eax\" parm [dx] [eax];");
                h.AppendLine("uint8_t inportb(uint16_t port);");
                h.AppendLine("#pragma aux inportb = \"in al, dx\" parm [dx] value [al];");
                h.AppendLine("uint16_t inportw(uint16_t port);");
                h.AppendLine("#pragma aux inportw = \"in ax, dx\" parm [dx] value [ax];");
                h.AppendLine("uint32_t inportd(uint16_t port);");
                h.AppendLine("#pragma aux inportd = \"in eax, dx\" parm [dx] value [eax];");
                h.AppendLine("#else");
                h.AppendLine("#define outportb(p,v) (void)0");
                h.AppendLine("#define inportb(p) 0");
                h.AppendLine("#endif");
                h.AppendLine();
                h.AppendLine("#if defined(__DJGPP__)");
                h.AppendLine("#include <dpmi.h>");
                h.AppendLine("#define DOS_INT(intno) do { \\");
                h.AppendLine("    __dpmi_regs __r; memset(&__r, 0, sizeof(__r)); \\");
                h.AppendLine("    __r.x.eax = (unsigned long)eax; __r.x.ebx = (unsigned long)ebx; __r.x.ecx = (unsigned long)ecx; __r.x.edx = (unsigned long)edx; \\");
                h.AppendLine("    __r.x.esi = (unsigned long)esi; __r.x.edi = (unsigned long)edi; \\");
                h.AppendLine("    __dpmi_int((intno), &__r); \\");
                h.AppendLine("    eax = (uint32_t)__r.x.eax; ebx = (uint32_t)__r.x.ebx; ecx = (uint32_t)__r.x.ecx; edx = (uint32_t)__r.x.edx; \\");
                h.AppendLine("    esi = (uint32_t)__r.x.esi; edi = (uint32_t)__r.x.edi; \\");
                h.AppendLine("} while(0)");
                h.AppendLine("#elif defined(__WATCOMC__) && defined(__386__)");
                h.AppendLine("#include <i86.h>");
                h.AppendLine("#define DOS_INT(intno) do { \\");
                h.AppendLine("    union REGS __inr, __outr; memset(&__inr, 0, sizeof(__inr)); memset(&__outr, 0, sizeof(__outr)); \\");
                h.AppendLine("    __inr.x.eax = (unsigned long)eax; __inr.x.ebx = (unsigned long)ebx; __inr.x.ecx = (unsigned long)ecx; __inr.x.edx = (unsigned long)edx; \\");
                h.AppendLine("    __inr.x.esi = (unsigned long)esi; __inr.x.edi = (unsigned long)edi; \\");
                h.AppendLine("    int386((intno), &__inr, &__outr); \\");
                h.AppendLine("    eax = (uint32_t)__outr.x.eax; ebx = (uint32_t)__outr.x.ebx; ecx = (uint32_t)__outr.x.ecx; edx = (uint32_t)__outr.x.edx; \\");
                h.AppendLine("    esi = (uint32_t)__outr.x.esi; edi = (uint32_t)__outr.x.edi; \\");
                h.AppendLine("} while(0)");
                h.AppendLine("#else");
                h.AppendLine("#define DOS_INT(intno) do { (void)(intno); } while(0)");
                h.AppendLine("#endif");
                h.AppendLine();
                h.AppendLine("extern uint8_t* __mem; extern uint32_t __mem_size;");
                h.AppendLine("static inline void* __ptr(uint32_t addr) { return (addr < __mem_size) ? (void*)(__mem + addr) : (void*)0; }");
                h.AppendLine("static inline uint32_t __pop32(uint32_t *esp_) { uint32_t v = *(uint32_t*)__ptr(*esp_); *esp_ += 4; return v; }");
                h.AppendLine("extern uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;");
                h.AppendLine("#define ax (*(uint16_t*)&eax)");
                h.AppendLine("#define al (*(uint8_t*)&eax)");
                h.AppendLine("#define ah (*((uint8_t*)&eax + 1))");
                h.AppendLine("#define bx (*(uint16_t*)&ebx)");
                h.AppendLine("#define bl (*(uint8_t*)&ebx)");
                h.AppendLine("#define bh (*((uint8_t*)&ebx + 1))");
                h.AppendLine("#define cx (*(uint16_t*)&ecx)");
                h.AppendLine("#define cl (*(uint8_t*)&ecx)");
                h.AppendLine("#define ch (*((uint8_t*)&ecx + 1))");
                h.AppendLine("#define dx (*(uint16_t*)&edx)");
                h.AppendLine("#define dl (*(uint8_t*)&edx)");
                h.AppendLine("#define dh (*((uint8_t*)&edx + 1))");
                h.AppendLine("#define si (*(uint16_t*)&esi)");
                h.AppendLine("#define di (*(uint16_t*)&edi)");
                h.AppendLine("#define bp (*(uint16_t*)&ebp)");
                h.AppendLine("#define sp (*(uint16_t*)&esp)");
                h.AppendLine("extern uint32_t cs, ds, es, fs, gs, ss, dr0, dr1, dr2, dr3, dr6, dr7, _this, carry;");
                h.AppendLine("extern int jz, jnz, je, jne, jg, jge, jl, jle, ja, jae, jb, jbe, jo, jno, js, jns;");
                h.AppendLine("extern uint32_t __entry_jump_enabled, __entry_jump_target, __entry_jump_addr;");
                h.AppendLine("#define pop() __pop32(&esp)");
                h.AppendLine("#define strlen_rep(edi, al, ecx) __strlen_rep(edi, al, ecx)");
                h.AppendLine("static inline uint32_t __strlen_rep(uint32_t edi_, uint8_t al_, uint32_t ecx_) {");
                h.AppendLine("    uint32_t count = 0;");
                h.AppendLine("    while (ecx_ != 0) {");
                h.AppendLine("        if (*(uint8_t*)__ptr(edi_) == al_) break;");
                h.AppendLine("        edi_++; ecx_--; count++;");
                h.AppendLine("    }");
                h.AppendLine("    return count;");
                h.AppendLine("}");
                h.AppendLine("#define memset_32(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*4)");
                h.AppendLine("#define memset_16(dst, val, count) memset(__ptr((uint32_t)(dst)), val, (count)*2)");
                h.AppendLine("#define __builtin_bswap32(x) ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | (((x) & 0x000000FF) << 24))");
                h.AppendLine();

                foreach (var kvp in pages)
                {
                    var baseAddr = kvp.Key;
                    h.AppendLine($"extern uint8_t g_page_{baseAddr:X8}[0x1000];");
                }
                if (pages.Count > 0)
                {
                    h.AppendLine("static inline uint8_t* G(uint32_t addr)");
                    h.AppendLine("{");
                    h.AppendLine("    switch (addr & 0xFFFFF000u)");
                    h.AppendLine("    {");
                    foreach (var kvp in pages)
                    {
                        var baseAddr = kvp.Key;
                        h.AppendLine($"        case 0x{baseAddr:X8}u: return &g_page_{baseAddr:X8}[addr & 0xFFFu];");
                    }
                    h.AppendLine("        default: return (uint8_t*)0;");
                    h.AppendLine("    }");
                    h.AppendLine("}");
                }

                foreach (var gsym in otherGlobals.OrderBy(x => x))
                    h.AppendLine($"extern uint8_t {gsym}[1];");

                foreach (var kvp in _addrToString.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var addr = kvp.Key;
                    var sym = kvp.Value;
                    h.AppendLine($"extern const char {sym}[];");
                }

                foreach (var psym in pseudoStringSymbols.OrderBy(x => x))
                {
                    if (knownStringSyms.Contains(psym)) continue;
                    h.AppendLine($"extern uint8_t {psym}[1];");
                }

                foreach (var foff in fieldOffsets.OrderBy(x => x))
                {
                    var off = foff.Substring(6);
                    h.AppendLine($"#define {foff} 0x{off}");
                }
                foreach (var psym in ptrSymbols.OrderBy(x => x))
                {
                    h.AppendLine($"extern uint8_t {psym}[1];");
                    var addr = psym.Substring(4);
                    h.AppendLine($"#define M_{psym} 0x{addr}");
                }
                h.AppendLine();

                foreach (var fn in functions.OrderBy(x => x.Name))
                {
                    var p = fn.Proto.Replace("(void)", "()");
                    h.AppendLine($"{p};");
                }
                foreach (var kvp in otherFunctions.OrderBy(x => x.Key))
                    h.AppendLine($"{kvp.Value.proto};");

                var functionsByName = functions.ToDictionary(f => f.Name, f => f, StringComparer.OrdinalIgnoreCase);
                var sortedFuncs = functions.ToList();

                // Chunking semantics:
                // - Historical behavior: chunkSize == functions-per-chunk.
                // - CLI behavior: chunkSize is desired chunk count (chunkSizeIsCount=true).
                var functionsPerChunk = chunkSize;
                if (chunkSizeIsCount && chunkSize > 0)
                {
                    var desiredChunks = Math.Max(1, chunkSize);
                    functionsPerChunk = (int)Math.Ceiling(sortedFuncs.Count / (double)desiredChunks);
                }
                if (functionsPerChunk <= 0)
                    functionsPerChunk = 200;
                
                var buildBat = new StringBuilder();
                buildBat.Append("@echo off\r\n");
                buildBat.Append("call C:\\WATCOM\\OWSETENV.BAT\r\n");
                buildBat.Append("echo Compiling data...\r\n");
                buildBat.Append("wcc386 -zastd=c99 -6r -s -zq -fo=bdata.obj bdata.c\r\n");
                buildBat.Append("echo Compiling main...\r\n");
                buildBat.Append("wcc386 -zastd=c99 -6r -s -zq -fo=main.obj main.c\r\n");
                
                var linkerRsp = new StringBuilder();
                linkerRsp.Append("name blst\r\n");
                linkerRsp.Append("system dos4g\r\n");
                linkerRsp.Append("option quiet\r\n");
                linkerRsp.Append("option stack=0x8000\r\n");
                linkerRsp.Append("option start=_cstart_\r\n");
                linkerRsp.Append("libpath C:\\WATCOM\\LIB386\r\n");
                linkerRsp.Append("libpath C:\\WATCOM\\LIB386\\DOS\r\n");
                linkerRsp.Append("file main.obj\r\n");
                linkerRsp.Append("file bdata.obj\r\n");

                // Entry point: initialize an emulated guest stack for esp/pop() and transfer control into translated code.
                var mainSb = new StringBuilder();
                mainSb.AppendLine("#include \"blst.h\"");
                mainSb.AppendLine("#include <ctype.h>");
                mainSb.AppendLine();
                mainSb.AppendLine("/* NOTE: guest linear memory backing is allocated at runtime into __mem. */");
                if (haveLeMeta)
                {
                    mainSb.AppendLine("/* NOTE: this build expects the original LE EXE to be present next to the rebuilt program. */");
                    mainSb.AppendLine();
                    mainSb.AppendLine("typedef struct { uint32_t base; uint32_t vsize; uint32_t flags; uint32_t pageMapIndex; uint32_t pageCount; } __le_obj;");
                    mainSb.AppendLine($"static const uint32_t __le_page_size = 0x{leHeader.PageSize:X}u;");
                    var leLastPageSize = leHeader.LastPageSize == 0 ? leHeader.PageSize : leHeader.LastPageSize;
                    mainSb.AppendLine($"static const uint32_t __le_last_page_size = 0x{leLastPageSize:X}u;");
                    mainSb.AppendLine($"static const uint32_t __le_num_pages = 0x{leHeader.NumberOfPages:X}u;");
                    mainSb.AppendLine($"static const uint32_t __le_data_pages_base = 0x{leDataPagesBase:X}u;");
                    mainSb.AppendLine($"static const uint32_t __le_entry_esp = 0x{leEntryEspLinear:X8}u;");
                    mainSb.AppendLine($"static const uint32_t __le_entry_eip = 0x{leEntryEipLinear:X8}u;");
                    mainSb.AppendLine($"static const char* __le_orig_exe = \"{leOrigFilename.Replace("\\", "\\\\")}\";");
                    mainSb.AppendLine();
                    mainSb.AppendLine("// Best-effort DOS 8.3 fallback: try BASE~N.EXT when long filenames are not accessible.");
                    mainSb.AppendLine("static FILE* __fopen_le(const char* path)");
                    mainSb.AppendLine("{");
                    mainSb.AppendLine("    FILE* f = fopen(path, \"rb\");");
                    mainSb.AppendLine("    if (f) return f;");
                    mainSb.AppendLine();
                    mainSb.AppendLine("    const char* dot = strrchr(path, '.');");
                    mainSb.AppendLine("    if (!dot || dot == path) return (FILE*)0;");
                    mainSb.AppendLine();
                    mainSb.AppendLine("    char base6[7]; char ext3[4];");
                    mainSb.AppendLine("    unsigned bi = 0, ei = 0;");
                    mainSb.AppendLine("    memset(base6, 0, sizeof(base6));");
                    mainSb.AppendLine("    memset(ext3, 0, sizeof(ext3));");
                    mainSb.AppendLine("    for (const char* p = path; p < dot && bi < 6; p++) {");
                    mainSb.AppendLine("        unsigned char c = (unsigned char)*p;");
                    mainSb.AppendLine("        if (isalnum(c)) base6[bi++] = (char)toupper(c);");
                    mainSb.AppendLine("    }");
                    mainSb.AppendLine("    for (const char* p = dot + 1; *p && ei < 3; p++) {");
                    mainSb.AppendLine("        unsigned char c = (unsigned char)*p;");
                    mainSb.AppendLine("        if (isalnum(c)) ext3[ei++] = (char)toupper(c);");
                    mainSb.AppendLine("    }");
                    mainSb.AppendLine("    if (bi == 0 || ei == 0) return (FILE*)0;");
                    mainSb.AppendLine();
                    mainSb.AppendLine("    char sfn[16];");
                    mainSb.AppendLine("    for (unsigned n = 1; n <= 9; n++) {");
                    mainSb.AppendLine("        sprintf(sfn, \"%s~%u.%s\", base6, n, ext3);");
                    mainSb.AppendLine("        f = fopen(sfn, \"rb\");");
                    mainSb.AppendLine("        if (f) return f;");
                    mainSb.AppendLine("    }");
                    mainSb.AppendLine("    return (FILE*)0;");
                    mainSb.AppendLine("}");
                    mainSb.AppendLine();

                    mainSb.AppendLine("static const __le_obj __le_objs[] = {");
                    foreach (var o in leObjects.OrderBy(x => x.Index))
                    {
                        mainSb.AppendLine($"    {{ 0x{o.BaseAddress:X8}u, 0x{o.VirtualSize:X}u, 0x{o.Flags:X8}u, 0x{o.PageMapIndex:X}u, 0x{o.PageCount:X}u }},");
                    }
                    mainSb.AppendLine("};");
                    mainSb.AppendLine();
                    mainSb.AppendLine("static const uint16_t __le_page_map[] = {");
                    // Emit page map in compact lines to avoid pathological line lengths.
                    for (var i = 0; i < lePageMap.Length; i++)
                    {
                        if (i % 16 == 0) mainSb.Append("    ");
                        mainSb.Append($"0x{(ushort)lePageMap[i]:X4}, ");
                        if (i % 16 == 15 || i == lePageMap.Length - 1) mainSb.AppendLine();
                    }
                    mainSb.AppendLine("};");
                    mainSb.AppendLine();
                    mainSb.AppendLine("static int __load_le_image(const char* path)");
                    mainSb.AppendLine("{");
                    mainSb.AppendLine("    FILE* f = __fopen_le(path);");
                    mainSb.AppendLine("    if (!f) return 0;");
                    mainSb.AppendLine("    unsigned oi;");
                    mainSb.AppendLine("    uint32_t i;");
                    mainSb.AppendLine("    for (oi = 0; oi < (unsigned)(sizeof(__le_objs)/sizeof(__le_objs[0])); oi++)");
                    mainSb.AppendLine("    {");
                    mainSb.AppendLine("        const __le_obj* o = &__le_objs[oi];");
                    mainSb.AppendLine("        for (i = 0; i < o->pageCount; i++)");
                    mainSb.AppendLine("        {");
                    mainSb.AppendLine("            uint32_t mapIndex0 = (o->pageMapIndex - 1u) + i;");
                    mainSb.AppendLine("            if (mapIndex0 >= (uint32_t)(sizeof(__le_page_map)/sizeof(__le_page_map[0]))) break;");
                    mainSb.AppendLine("            uint32_t phys = (uint32_t)__le_page_map[mapIndex0]; /* 1-based physical page */");
                    mainSb.AppendLine("            if (phys == 0) continue; /* zero-fill */");
                    mainSb.AppendLine("            uint32_t bytesThisPage = (phys == __le_num_pages) ? __le_last_page_size : __le_page_size;");
                    mainSb.AppendLine("            uint32_t fileOff = __le_data_pages_base + (phys - 1u) * __le_page_size;");
                    mainSb.AppendLine("            if (fseek(f, (long)fileOff, SEEK_SET) != 0) { fclose(f); return 0; }");
                    mainSb.AppendLine("            void* dst = __ptr(o->base + i * __le_page_size);");
                    mainSb.AppendLine("            if (!dst) { fclose(f); return 0; }");
                    mainSb.AppendLine("            if (fread(dst, 1, (size_t)bytesThisPage, f) != (size_t)bytesThisPage) { fclose(f); return 0; }");
                    mainSb.AppendLine("        }");
                    mainSb.AppendLine("    }");
                    mainSb.AppendLine("    fclose(f);");
                    mainSb.AppendLine("    return 1;");
                    mainSb.AppendLine("}");
                    mainSb.AppendLine();
                }
                mainSb.AppendLine();
                mainSb.AppendLine("int main(void)");
                mainSb.AppendLine("{");
                if (haveLeMeta)
                {
                    mainSb.AppendLine("    /* Allocate guest linear memory window based on LE object layout. */");
                    mainSb.AppendLine($"    __mem_size = 0x{leSuggestedMemSize:X}u;");
                }
                else
                {
                    mainSb.AppendLine("    /* Allocate a conservative guest memory window (best-effort). */");
                    mainSb.AppendLine("    __mem_size = 0x02000000u; /* 32 MiB */");
                }
                mainSb.AppendLine("    __mem = (uint8_t*)malloc(__mem_size);");
                mainSb.AppendLine("    if (!__mem) return 1;");
                mainSb.AppendLine("    memset(__mem, 0, __mem_size);");
                if (haveLeMeta)
                {
                    mainSb.AppendLine("    if (!__load_le_image(__le_orig_exe)) return 2;");
                    mainSb.AppendLine("    esp = __le_entry_esp;");
                }
                else
                {
                    mainSb.AppendLine("    esp = 0x00100000u; // best-effort stack top");
                }
                mainSb.AppendLine("    ebp = esp;");
                mainSb.AppendLine();
                mainSb.AppendLine("    __entry_jump_enabled = 0;");
                mainSb.AppendLine("    __entry_jump_target = 0;");
                mainSb.AppendLine("    __entry_jump_addr = 0;");
                mainSb.AppendLine();

                if (!string.IsNullOrWhiteSpace(entryDirectFunc))
                {
                    mainSb.AppendLine($"    {SanitizeLabel(entryDirectFunc)}();");
                }
                else if (entryLinear.HasValue && !string.IsNullOrWhiteSpace(entryContainerFunc) && entryJumpAddr.HasValue)
                {
                    mainSb.AppendLine("    __entry_jump_enabled = 1;");
                    mainSb.AppendLine($"    __entry_jump_target = 0x{entryLinear.Value:X8}u;");
                    mainSb.AppendLine($"    __entry_jump_addr = 0x{entryJumpAddr.Value:X8}u;");
                    mainSb.AppendLine($"    {SanitizeLabel(entryContainerFunc)}();");
                }
                else
                {
                    mainSb.AppendLine("    // NOTE: no LE entry address detected in disassembly header.");
                }

                mainSb.AppendLine("    return 0;");
                mainSb.AppendLine("}");

                files["main.c"] = mainSb.ToString().Replace("\n", "\r\n");

                var calledFuncs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                for (int i = 0; i < sortedFuncs.Count; i += functionsPerChunk)
                {
                    var partNum = i / functionsPerChunk;
                    var chunk = sortedFuncs.Skip(i).Take(functionsPerChunk);
                    var csb = new StringBuilder();
                    csb.Append("#include \"blst.h\"\r\n");
                    csb.Append("\r\n");
                    foreach (var fn in chunk)
                    {
                        csb.Append(EmitFunctionBody(fn, labelByAddr, functionsByName, otherFunctions, entryLinear, entryContainerFunc, entryJumpAddr));
                        
                        // Collect all function calls from this function to check for missing ones later
                        foreach (var block in fn.Blocks)
                        {
                            foreach (var line in block.Lines)
                            {
                                if (line.Kind != ParsedLineKind.Instruction) continue;
                                // If the disassembly already contains func_XXXXXXXX, collect it.
                                var m = Regex.Match(line.Asm + " " + (line.Raw ?? "") + " " + (line.Comment ?? ""), @"\bfunc_(?<addr>[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                                if (m.Success) calledFuncs.Add($"func_{m.Groups["addr"].Value.ToUpperInvariant()}");

                                // Also collect numeric call targets (e.g. call 0Dh) which ResolveCallTarget
                                // upgrades into func_XXXXXXXX in generated C.
                                var asm = (line.Asm ?? string.Empty).TrimStart();
                                if (asm.StartsWith("call", StringComparison.OrdinalIgnoreCase))
                                {
                                    var ops = asm.Substring(4).Trim();
                                    if (!string.IsNullOrWhiteSpace(ops))
                                    {
                                        var t = ResolveCallTarget(ops, labelByAddr);
                                        if (t.StartsWith("func_", StringComparison.OrdinalIgnoreCase))
                                            calledFuncs.Add(t);
                                    }
                                }
                            }
                        }
                    }
                    files[$"b{partNum}.c"] = csb.ToString();
                    
                    buildBat.Append($"echo Compiling chunk {partNum}...\r\n");
                    buildBat.Append($"wcc386 -zastd=c99 -6r -s -zq -fo=b{partNum}.obj b{partNum}.c\r\n");
                    linkerRsp.Append($"file b{partNum}.obj\r\n");
                }
                
                buildBat.Append("echo Linking...\r\n");
                buildBat.Append("wlink @blst.lnk\r\n");
                
                linkerRsp.Append("library clib3r.lib\r\n");
                linkerRsp.Append("library math3r.lib\r\n");

                var definedFuncs = new HashSet<string>(functions.Select(f => f.Name), StringComparer.OrdinalIgnoreCase);

                // If the LE entrypoint is in the middle of another function, emit a small wrapper at the
                // entry linear address so users can call it directly (e.g. func_000A5C24()).
                // This helps debugging and avoids Watcom implicit-declaration/name-decoration pitfalls.
                string entryWrapperName = null;
                bool emitEntryWrapper = false;
                if (entryLinear.HasValue && entryJumpAddr.HasValue && !string.IsNullOrWhiteSpace(entryContainerFunc))
                {
                    entryWrapperName = $"func_{entryLinear.Value:X8}";
                    if (!definedFuncs.Contains(entryWrapperName))
                    {
                        emitEntryWrapper = true;
                        definedFuncs.Add(entryWrapperName);
                    }
                }
                var neededStubs = calledFuncs.Where(f => !definedFuncs.Contains(f)).OrderBy(x => x).ToList();
                
                if (calledFuncs.Count > 0)
                    Console.Error.WriteLine($"[DECOMP] Collected {calledFuncs.Count} potential function calls. {definedFuncs.Count} defined. {neededStubs.Count} stubs needed.");

                // Add missing-call prototypes so Watcom doesn't implicitly-declare them (which can alter calling convention/name decoration).
                foreach (var stub in neededStubs)
                {
                    var stubName = SanitizeLabel(stub);
                    h.AppendLine($"uint32_t {stubName}();");
                }

                if (emitEntryWrapper)
                {
                    h.AppendLine($"uint32_t {SanitizeLabel(entryWrapperName)}();");
                }

                h.AppendLine("#endif");
                files["blst.h"] = h.ToString();

                files["build.bat"] = buildBat.ToString();
                files["blst.lnk"] = linkerRsp.ToString();

                var d = new StringBuilder();
                d.AppendLine("#include \"blst.h\"");
                d.AppendLine();
                d.AppendLine("uint8_t* __mem; uint32_t __mem_size;");
                d.AppendLine();
                d.AppendLine("uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;");
                d.AppendLine("uint32_t cs, ds, es, fs, gs, ss, dr0, dr1, dr2, dr3, dr6, dr7, _this, carry;");
                d.AppendLine("int jz, jnz, je, jne, jg, jge, jl, jle, ja, jae, jb, jbe, jo, jno, js, jns;");
                d.AppendLine("uint32_t __entry_jump_enabled, __entry_jump_target, __entry_jump_addr;");
                d.AppendLine();

                if (emitEntryWrapper)
                {
                    d.AppendLine($"uint32_t {SanitizeLabel(entryWrapperName)}()");
                    d.AppendLine("{");
                    d.AppendLine("    __entry_jump_enabled = 1;");
                    d.AppendLine($"    __entry_jump_target = 0x{entryLinear.Value:X8}u;");
                    d.AppendLine($"    __entry_jump_addr = 0x{entryJumpAddr.Value:X8}u;");
                    d.AppendLine($"    return {SanitizeLabel(entryContainerFunc)}();");
                    d.AppendLine("}");
                    d.AppendLine();
                }
                foreach (var stub in neededStubs)
                {
                    var stubName = SanitizeLabel(stub);
                    d.AppendLine($"uint32_t {stubName}() {{ return 0; }}");
                }
                d.AppendLine();

                foreach (var kvp in pages)
                {
                    var baseAddr = kvp.Key;
                    d.AppendLine($"uint8_t g_page_{baseAddr:X8}[0x1000];");
                }
                foreach (var gsym in otherGlobals.OrderBy(x => x))
                    d.AppendLine($"uint8_t {gsym}[1];");

                foreach (var kvp in _addrToString.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
                {
                    var addr = kvp.Key;
                    var sym = kvp.Value;
                    var lit = _addrToStringLiteral.TryGetValue(addr, out var sLit) ? sLit : "\"\"";
                    d.AppendLine($"const char {sym}[] = {lit};");
                }

                foreach (var psym in pseudoStringSymbols.OrderBy(x => x))
                {
                    if (knownStringSyms.Contains(psym)) continue;
                    d.AppendLine($"uint8_t {psym}[1];");
                }
                foreach (var psym in ptrSymbols.OrderBy(x => x))
                    d.AppendLine($"uint8_t {psym}[1];");

                files["bdata.c"] = d.ToString();
            }

            return (true, files, string.Empty);
        }

        private static string EmitFunctionBody(
            ParsedFunction fn,
            Dictionary<string, string> labelByAddr,
            Dictionary<string, ParsedFunction> functionsByName,
            Dictionary<string, (string proto, int argCount)> otherFunctions,
            uint? entryLinear,
            string entryContainerFunc,
            uint? entryJumpAddr)
        {
            var sb = new StringBuilder();
            var proto = fn.Proto;
            var allBytes = string.Join("", fn.Blocks.SelectMany(b => b.Lines).Select(l => l.BytesHex));
            var hashStr = string.Empty;
            if (!string.IsNullOrEmpty(allBytes))
            {
                using (var md5 = MD5.Create())
                {
                    var hash = md5.ComputeHash(Encoding.ASCII.GetBytes(allBytes));
                    hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }

            sb.AppendLine(proto + "");
            sb.AppendLine("{");
            if (!string.IsNullOrEmpty(hashStr))
            {
                sb.AppendLine($"    // FIDELITY: {hashStr} (checksum of raw bytes)");
            }

            var regs = CollectRegistersUsed(fn);
            foreach (var r in new[] { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" })
                regs.Add(r);
            var stackVars = CollectStackVarsUsed(fn);

            var argVars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var protoArgMatches = Regex.Matches(proto, @"\b(?<name>arg_[0-9A-Fa-f]+)\b");
            foreach (Match am in protoArgMatches) argVars.Add(am.Groups["name"].Value.ToLowerInvariant());
            stackVars.RemoveWhere(v => argVars.Contains(v));

            var regDecls = FormatRegisterDeclarations(regs);
            if (!string.IsNullOrEmpty(regDecls))
                sb.Append(regDecls);

            if (stackVars.Any())
            {
                var byType = stackVars.GroupBy(v => fn.InferredTypes.GetValueOrDefault(v, "uint32_t"));
                foreach (var g in byType.OrderBy(x => x.Key))
                {
                    sb.AppendLine($"    {g.Key} " + string.Join(", ", g.OrderBy(v => v)) + ";");
                }
            }

            var entryLabel = entryJumpAddr.HasValue ? $"__entry_{entryJumpAddr.Value:X8}" : null;
            var shouldInjectEntryJump = entryLinear.HasValue
                && entryJumpAddr.HasValue
                && !string.IsNullOrWhiteSpace(entryContainerFunc)
                && fn.Name.Equals(entryContainerFunc, StringComparison.OrdinalIgnoreCase);

            if (shouldInjectEntryJump)
            {
                sb.AppendLine($"    if (__entry_jump_enabled && __entry_jump_target == 0x{entryLinear.Value:X8}u && __entry_jump_addr == 0x{entryJumpAddr.Value:X8}u) {{ __entry_jump_enabled = 0; goto {entryLabel}; }}");
            }

            var pending = new PendingFlags();
            var referencedLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var block in fn.Blocks)
            {
                foreach (var line in block.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    var lblMatches = Regex.Matches(line.Asm + " " + line.Raw, @"\b(?<lbl>(loc|bb)_[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                    foreach (Match lm in lblMatches) 
                        referencedLabels.Add(lm.Groups["lbl"].Value);

                    if (IsJccLine(line, out _, out var target))
                    {
                        var lbl = labelByAddr.GetValueOrDefault(target.ToUpperInvariant().PadLeft(8, '0'));
                        if (lbl != null) referencedLabels.Add(lbl);
                    }
                }
            }

            IdentifySimpleStructures(fn);

            int indent = 1;
            var nestedFollows = new Stack<string>();
            var emittedEntryLabel = false;
            foreach (var block in fn.Blocks)
            {
                while (nestedFollows.Count > 0 && nestedFollows.Peek().Equals(block.Label, StringComparison.OrdinalIgnoreCase))
                {
                    var closed = nestedFollows.Pop();
                    indent = Math.Max(1, indent - 1);
                    var parentDiamond = fn.Blocks.FirstOrDefault(b => b.StructuredType == "diamond-header" && b.StructuredFollow != null && b.StructuredFollow.Equals(closed, StringComparison.OrdinalIgnoreCase));
                    if (parentDiamond != null)
                    {
                        sb.AppendLine(new string(' ', indent * 4) + "} else {");
                        indent++;
                        nestedFollows.Push(parentDiamond.SecondaryFollow);
                    }
                    else
                    {
                        sb.AppendLine(new string(' ', indent * 4) + "}");
                    }
                }

                var state = fn.BlockEntryStates.GetValueOrDefault(block.Label)?.Clone() ?? new DecompilationState();
                var sanitizedLabel = SanitizeLabel(block.Label);
                sb.AppendLine($"{new string(' ', Math.Max(0, (indent - 1) * 4))}{sanitizedLabel}:;");

                if (block.StructuredType == "while-true")
                {
                    sb.AppendLine(new string(' ', indent * 4) + "while (1) {");
                    indent++;
                    var nextIdx = fn.Blocks.IndexOf(block) + 1;
                    var nextLabel = (nextIdx < fn.Blocks.Count) ? fn.Blocks[nextIdx].Label : "___END_OF_FUNCTION___";
                    nestedFollows.Push(nextLabel);
                }
                else if (block.StructuredType == "if-then" || block.StructuredType == "diamond-header")
                {
                    sb.AppendLine(new string(' ', indent * 4) + $"if ({block.StructuredCondition}) {{");
                    indent++;
                    nestedFollows.Push(block.StructuredFollow);
                }

                var blockLines = new List<string>();
                var suppressTailAfterRetDecode = false;
                for (var lineIdx = 0; lineIdx < block.Lines.Count; lineIdx++)
                {
                    var item = block.Lines[lineIdx];

                    if (shouldInjectEntryJump && !emittedEntryLabel && item.Kind == ParsedLineKind.Instruction && (uint)item.Address == entryJumpAddr.Value)
                    {
                        blockLines.Add($"{entryLabel}:;");
                        emittedEntryLabel = true;
                    }

                    if (item.Kind == ParsedLineKind.Comment)
                    {
                        blockLines.Add("// " + item.Raw.TrimStart(';').Trim());
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(item.Comment) &&
                        item.Comment.Contains("decoded after RET", StringComparison.OrdinalIgnoreCase))
                    {
                        suppressTailAfterRetDecode = true;
                        pending.Clear();
                        blockLines.Add("// NOTE: omitted tail bytes decoded after RET (likely data/padding)");
                        continue;
                    }

                    if (suppressTailAfterRetDecode)
                        continue;

                    if (lineIdx == block.Lines.Count - 1 && item.Kind == ParsedLineKind.Instruction && !string.IsNullOrEmpty(block.StructuredType))
                    {
                        if (item.Mnemonic?.Equals("jmp", StringComparison.OrdinalIgnoreCase) == true || IsJccLine(item, out _, out _))
                        {
                            continue;
                        }
                    }

                    if (item.Kind == ParsedLineKind.Instruction && (item.Mnemonic?.Equals("call", StringComparison.OrdinalIgnoreCase) == true || item.Asm.TrimStart().StartsWith("call", StringComparison.OrdinalIgnoreCase)))
                    {
                        var decoration = string.Empty;
                        if (_addrToCallDecoration.TryGetValue(item.AddrHex, out var deco))
                        {
                            decoration = deco;
                        }

                        var hint = string.Empty;
                        for (var j = lineIdx + 1; j < block.Lines.Count && j < lineIdx + 5; j++)
                        {
                            var peek = block.Lines[j];
                            if (peek.Kind == ParsedLineKind.Comment && (peek.Raw.Contains("CALLHINT:") || peek.Raw.Contains("STRCALL:")))
                            {
                                hint = peek.Raw;
                                break;
                            }
                            if (peek.Kind == ParsedLineKind.Instruction) break;
                        }

                        if (!string.IsNullOrWhiteSpace(hint))
                        {
                            var callStmt = TranslateCallWithHint(item, hint, labelByAddr, pending, fn, state);
                            if (callStmt != null)
                            {
                                blockLines.Add(callStmt);
                            }
                            continue;
                        }
                    }

                    var stmt = TranslateInstructionToPseudoC(item, labelByAddr, pending, fn, functionsByName, otherFunctions, state);
                    if (!string.IsNullOrWhiteSpace(stmt))
                    {
                        var extraLabels = Regex.Matches(stmt, @"\b(?<lbl>(loc|bb)_[0-9A-Fa-f]{8})\b", RegexOptions.IgnoreCase);
                        foreach (Match lm in extraLabels) referencedLabels.Add(lm.Value);

                        if (stmt == "return;")
                        {
                            if (!string.IsNullOrWhiteSpace(pending.LastEaxAssignment))
                            {
                                blockLines.Add($"return {pending.LastEaxAssignment};");
                                pending.LastEaxAssignment = null;
                            }
                            else
                            {
                                blockLines.Add("return eax;");
                            }
                        }
                        else
                        {
                            blockLines.Add(stmt);
                        }
                    }
                }

                var optimized = OptimizeStatements(blockLines);
                foreach (var s in optimized)
                {
                    sb.AppendLine(new string(' ', indent * 4) + s);
                }
            }

            while (nestedFollows.Count > 0)
            {
                nestedFollows.Pop();
                indent = Math.Max(1, indent - 1);
                sb.AppendLine(new string(' ', indent * 4) + "}");
            }

            var blocksInFunc = new HashSet<string>(fn.Blocks.Select(b => b.Label), StringComparer.OrdinalIgnoreCase);
            foreach (var missing in referencedLabels.Where(l => !blocksInFunc.Contains(l)).OrderBy(l => l))
            {
                sb.AppendLine($"{SanitizeLabel(missing)}:; // missing label from this function slice");
            }

            sb.AppendLine("    return eax;");
            sb.AppendLine("}");
            sb.AppendLine();
            return sb.ToString();
        }

        private static (bool ok, string[] lines, string error) TrySliceToSingleFunction(string[] lines, string onlyFunction)
        {
            if (lines == null || lines.Length == 0)
                return (true, lines, string.Empty);

            var needle = onlyFunction.Trim();
            if (needle.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                needle = needle.Substring(2);
            needle = needle.Trim();

            if (Regex.IsMatch(needle, @"^[0-9A-Fa-f]{1,8}$"))
            {
                needle = needle.PadLeft(8, '0').ToUpperInvariant();
                needle = "func_" + needle;
            }

            if (!needle.StartsWith("func_", StringComparison.OrdinalIgnoreCase))
                needle = "func_" + needle;

            var start = -1;
            for (var i = 0; i < lines.Length; i++)
            {
                var t = lines[i].Trim();
                if (t.StartsWith(needle + ":", StringComparison.OrdinalIgnoreCase))
                {
                    start = i;
                    break;
                }
            }

            if (start < 0)
            {
                var available = new List<string>();
                for (var i = 0; i < lines.Length; i++)
                {
                    var t = lines[i].Trim();
                    var m = Regex.Match(t, @"^func_[0-9A-Fa-f]{8}:\s*$");
                    if (m.Success)
                    {
                        available.Add(t.TrimEnd(':'));
                        if (available.Count >= 15)
                            break;
                    }
                }

                var msg = $"Requested function '{needle}' not found in asm input.";
                if (available.Count > 0)
                    msg += " Available (first 15): " + string.Join(", ", available);
                return (false, lines, msg);
            }

            var end = lines.Length;
            for (var i = start + 1; i < lines.Length; i++)
            {
                var t = lines[i].Trim();
                if (Regex.IsMatch(t, @"^func_[0-9A-Fa-f]{8}:\s*$"))
                {
                    end = i;
                    break;
                }
            }

            // Slice exactly to the function for speed.
            return (true, lines.Skip(start).Take(end - start).ToArray(), string.Empty);
        }

        private static HashSet<string> CollectRegistersUsed(ParsedFunction fn)
        {
            var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var commonRegs = new[] { 
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
                "cs", "ds", "es", "fs", "gs", "ss", "this",
                "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
                "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7"
            };

            // Pre-compile regex for performance
            var regPattern = @"\b(" + string.Join("|", commonRegs) + @")\b";
            var regRegex = new Regex(regPattern, RegexOptions.IgnoreCase);

            foreach (var block in fn.Blocks)
            {
                foreach (var line in block.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    var matches = regRegex.Matches(line.Asm);
                    foreach (Match m in matches)
                    {
                        var reg = m.Value.ToLowerInvariant();
                        // Filter out sub-registers if the 32-bit version is also present? 
                        // Actually let's just use a map to the "root" register to ensure we declare the root.
                        res.Add(reg);
                    }
                }
            }
            return res;
        }

        private static string FormatRegisterDeclarations(HashSet<string> regs)
        {
            if (regs == null || regs.Count == 0) return string.Empty;

            var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var subRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                ["al"]="eax", ["ah"]="eax", ["ax"]="eax", ["eax"]="eax",
                ["bl"]="ebx", ["bh"]="ebx", ["bx"]="ebx", ["ebx"]="ebx",
                ["cl"]="ecx", ["ch"]="ecx", ["cx"]="ecx", ["ecx"]="ecx",
                ["dl"]="edx", ["dh"]="edx", ["dx"]="edx", ["edx"]="edx",
                ["si"]="esi", ["esi"]="esi",
                ["di"]="edi", ["edi"]="edi",
                ["bp"]="ebp", ["ebp"]="ebp",
                ["sp"]="esp", ["esp"]="esp",
                ["cs"]="cs", ["ds"]="ds", ["es"]="es", ["fs"]="fs", ["gs"]="gs", ["ss"]="ss",
                ["this"]="_this"
            };

            var globals = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
                "cs", "ds", "es", "fs", "gs", "ss", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "_this", "carry"
            };

            foreach (var r in regs)
            {
                if (map.TryGetValue(r, out var root))
                {
                    if (globals.Contains(root)) continue;
                    roots.Add(root);
                    if (r != root) subRegs.Add(r);
                }
                else
                {
                    if (globals.Contains(r)) continue;
                    roots.Add(r);
                }
            }

            var sb = new StringBuilder();
            if (roots.Any())
            {
                sb.AppendLine("    uint32_t " + string.Join(", ", roots.OrderBy(x => x)) + ";");
            }
            if (subRegs.Any())
            {
                var bySize = subRegs.GroupBy(r => {
                    if (r.EndsWith("l") || r.EndsWith("h")) return "uint8_t";
                    if (r.EndsWith("x") || r == "si" || r == "di" || r == "bp" || r == "sp") return "uint16_t";
                    return "uint32_t";
                });
                foreach (var g in bySize.OrderBy(x => x.Key))
                {
                    sb.AppendLine($"    {g.Key} " + string.Join(", ", g.OrderBy(x => x)) + "; // sub-registers");
                }
            }
            return sb.ToString();
        }

        private static HashSet<string> CollectStackVarsUsed(ParsedFunction fn)
        {
            var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var varRegex = new Regex(@"\b(local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+|out_[A-Za-z0-9]+|opt_[A-Za-z0-9]+|ptr_local_[0-9A-Fa-f]+|ptr_arg_[0-9A-Fa-f]+)\b", RegexOptions.IgnoreCase);

            foreach (var block in fn.Blocks)
            {
                foreach (var line in block.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    
                    // Also scan for ebp offsets that will become vars
                    var ebpMatch = Regex.Matches(line.Asm, @"ebp\s*(?<sign>[\+\-])\s*(?<off>0x[0-9A-Fa-f]+|[0-9]+|(?<hexoff>[0-9A-Fa-f]+)h)", RegexOptions.IgnoreCase);
                    foreach (Match m in ebpMatch)
                    {
                        var sign = m.Groups["sign"].Value;
                        var offStr = m.Groups["off"].Value;
                        uint off;
                        if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase)) off = Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                        else if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) off = Convert.ToUInt32(offStr.Substring(2), 16);
                        else uint.TryParse(offStr, out off);

                        if (sign == "-") res.Add($"local_{off:x}".ToLowerInvariant());
                        else if (off >= 8) res.Add($"arg_{(off - 8) / 4:x}".ToLowerInvariant());
                    }

                    var matches = varRegex.Matches(line.Asm);
                    foreach (Match m in matches)
                        res.Add(m.Value.ToLowerInvariant());

                    if (!string.IsNullOrEmpty(line.Comment))
                    {
                        var cm = varRegex.Matches(line.Comment);
                        foreach (Match m in cm)
                            res.Add(m.Value.ToLowerInvariant());
                    }
                }
            }
            return res;
        }

        private static string TranslateCallWithHint(ParsedInsOrComment callIns, string hint, Dictionary<string, string> labelByAddr, PendingFlags pending, ParsedFunction fn, DecompilationState state)
        {
            var targetRaw = callIns.Asm.Substring(4).Trim();
            var target = ResolveCallTarget(targetRaw, labelByAddr);

            var argsMatch = Regex.Match(hint, @"args~(?<count>\d+)");
            var argcMatch = Regex.Match(callIns.Comment, @"ARGC:\s+~(?<count>\d+)");
            var retMatch = Regex.Match(hint, @"ret=(?<ret>[^\s,)]+)");
            var regHints = Regex.Matches(hint, @"reg~(?<reg>[a-z]{2,3})=(?<val>\[[^\]]+\]|[^\s,]+)");

            int totalArgs = 0;
            if (argsMatch.Success) int.TryParse(argsMatch.Groups["count"].Value, out totalArgs);
            else if (argcMatch.Success) int.TryParse(argcMatch.Groups["count"].Value, out totalArgs);

            var argList = new List<string>();
            foreach (Match rm in regHints)
            {
                var r = rm.Groups["reg"].Value;
                var v = rm.Groups["val"].Value.Trim();
                if (v.EndsWith(",")) v = v.Substring(0, v.Length - 1);
                argList.Add($"{r}={NormalizeAsmOperandToC(v, false, fn)}");
            }

            // Pop remaining from stack
            int stackCount = totalArgs - argList.Count;
            if (stackCount > 0)
            {
                for (int i = 0; i < stackCount; i++)
                {
                    argList.Add(state.Stack.Count > 0 ? state.Pop() : $"stack_arg_{i}");
                }
            }

            var callStr = $"{target}({string.Join(", ", argList)})";
            pending.ClearAll();

            if (retMatch.Success)
            {
                var r = retMatch.Groups["ret"].Value.Trim().ToLowerInvariant();

                if (r == "eax")
                {
                    pending.LastEaxAssignment = callStr;
                    return null;
                }

                if (!string.IsNullOrWhiteSpace(r) && !r.Contains("unused"))
                    return $"{r} = {callStr};";
            }

            return callStr + ";";
        }

        private static string ResolveCallTarget(string opText, Dictionary<string, string> labelByAddr)
        {
            // Unify calls to use func_XXXXXXXX even if the disassembler gave it a loc_ or bb_ name
            var addrMatch = Regex.Match(opText, @"(?<pre>func|loc|bb)_(?<addr>[0-9A-Fa-f]{8})", RegexOptions.IgnoreCase);
            if (addrMatch.Success)
            {
                return SanitizeLabel("func_" + addrMatch.Groups["addr"].Value.ToUpperInvariant());
            }

            var mm = Regex.Match(opText.Trim(), @"(?:0x)?(?<addr>[0-9A-Fa-f]{1,8})");
            if (mm.Success)
            {
                var a = mm.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                if (labelByAddr.TryGetValue(a, out var lab))
                {
                    // Upgrade loc_/bb_ to func_ for any CALL target
                    if (lab.StartsWith("loc_", StringComparison.OrdinalIgnoreCase) || lab.StartsWith("bb_", StringComparison.OrdinalIgnoreCase))
                        return SanitizeLabel("func_" + a);
                    return SanitizeLabel(lab);
                }
                return "func_" + a;
            }
            return SanitizeLabel(opText);
        }

        private static string ResolveTarget(string opText, Dictionary<string, string> labelByAddr)
        {
            if (opText.StartsWith("func_", StringComparison.OrdinalIgnoreCase) || 
                opText.StartsWith("loc_", StringComparison.OrdinalIgnoreCase) || 
                opText.StartsWith("bb_", StringComparison.OrdinalIgnoreCase))
            {
                return SanitizeLabel(opText);
            }

            var mm = Regex.Match(opText.Trim(), @"(?:0x)?(?<addr>[0-9A-Fa-f]{1,8})");
            if (mm.Success)
            {
                var a = mm.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                if (labelByAddr.TryGetValue(a, out var lab))
                    return SanitizeLabel(lab);
                return "loc_" + a;
            }
            return SanitizeLabel(opText);
        }

        private static string InvertCondition(string jcc, PendingFlags pending)
        {
            var invJcc = jcc switch
            {
                "je" or "jz" => "jne",
                "jne" or "jnz" => "je",
                "jl" => "jge",
                "jle" => "jg",
                "jg" => "jle",
                "jge" => "jl",
                "jb" => "jae",
                "jbe" => "ja",
                "ja" => "jbe",
                "jae" => "jb",
                _ => null
            };

            if (invJcc == null) return null;
            return TryMakeConditionFromPending(invJcc, pending);
        }

        private static bool IsJccLine(ParsedInsOrComment ins, out string mn, out string targetAddr)
        {
            mn = null;
            targetAddr = null;
            if (ins == null || ins.Kind != ParsedLineKind.Instruction) return false;

            var m = Regex.Match(ins.Asm, @"^(?<mn>j[a-z]+)\s+0x(?<addr>[0-9A-Fa-f]{1,8})$");
            if (!m.Success) return false;

            mn = m.Groups["mn"].Value.ToLowerInvariant();
            targetAddr = m.Groups["addr"].Value.PadLeft(8, '0').ToUpperInvariant();
            return IsJcc(mn);
        }

        private enum ParsedLineKind
        {
            Instruction,
            Comment
        }

        private sealed class ParsedInsOrComment
        {
            public ParsedLineKind Kind;
            public string Raw;

            public string AddrHex;
            public string BytesHex;
            public string Asm;
            public string Mnemonic;
            public string Operands;
            public string Comment;
            public long Address => long.TryParse(AddrHex, System.Globalization.NumberStyles.HexNumber, null, out var a) ? a : 0;
        }

        private sealed class ParsedBlock
        {
            public string Label;
            public List<ParsedInsOrComment> Lines;
            public List<string> Successors = new List<string>();
            public List<string> Predecessors = new List<string>();
            public string StructuredType; // "if", "else", "while", "loop"
            public string StructuredCondition;
            public string StructuredFollow;
            public string SecondaryFollow;
            public string LastJumpMnemonic;
        }

        private sealed class ParsedFunction
        {
            public string Name;
            public List<string> HeaderComments;
            public List<ParsedBlock> Blocks;
            public Dictionary<string, string> InferredTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> LoopHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            public string RetType = "void";
            public string Proto;
            public int ArgCount;
            public Dictionary<string, DecompilationState> BlockEntryStates = new Dictionary<string, DecompilationState>(StringComparer.OrdinalIgnoreCase);
        }

        private static Dictionary<string, string> _addrToString = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, string> _addrToStringLiteral = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, string> _addrToGlobal = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, string> _addrToFuncName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static Dictionary<string, string> _addrToCallDecoration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<string> _x86Registers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
            "cs", "ds", "es", "fs", "gs", "ss"
        };

        private sealed class DecompilationState
        {
            public Dictionary<string, string> RegisterValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            public List<string> Stack = new List<string>();

            public DecompilationState Clone()
            {
                var ns = new DecompilationState();
                foreach (var kvp in RegisterValues) ns.RegisterValues[kvp.Key] = kvp.Value;
                ns.Stack.AddRange(Stack);
                return ns;
            }
            
            public string Resolve(string op)
            {
                if (string.IsNullOrWhiteSpace(op)) return op;
                if (RegisterValues.TryGetValue(op, out var val)) return val;

                // Best-effort substitution inside simple expressions.
                // This intentionally stays conservative: only replaces standalone register tokens.
                return Regex.Replace(
                    op,
                    @"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|ax|bx|cx|dx|si|di|bp|sp|al|ah|bl|bh|cl|ch|dl|dh)\b",
                    m =>
                    {
                        var r = m.Value;
                        if (!RegisterValues.TryGetValue(r, out var v) || string.IsNullOrWhiteSpace(v))
                            return r;
                        if (v.Contains(r, StringComparison.OrdinalIgnoreCase))
                            return r;
                        return v;
                    },
                    RegexOptions.IgnoreCase);
            }

            public void Set(string reg, string val)
            {
                if (IsRegister(reg)) {
                    if (val.Contains(reg, StringComparison.OrdinalIgnoreCase)) {
                        RegisterValues.Remove(reg);
                    } else {
                        RegisterValues[reg] = val;
                    }
                }
            }

            public void Push(string val) => Stack.Add(val);
            public string Pop() {
                if (Stack.Count > 0) {
                    var v = Stack[Stack.Count - 1];
                    Stack.RemoveAt(Stack.Count - 1);
                    return v;
                }
                return "pop()";
            }

            public void Clear(bool eaxOnly = false)
            {
                if (eaxOnly) RegisterValues.Remove("eax");
                else RegisterValues.Clear();
            }

            public void ClearVolatile()
            {
                var volatileRegs = new[] { "eax", "ecx", "edx", "ax", "cx", "dx", "al", "ah", "cl", "ch", "dl", "dh" };
                foreach (var r in volatileRegs) RegisterValues.Remove(r);
            }

            public static bool IsRegister(string r)
            {
                if (string.IsNullOrEmpty(r)) return false;
                var l = r.ToLowerInvariant();
                return l is "eax" or "ebx" or "ecx" or "edx" or "esi" or "edi" or "ebp" or "esp" 
                    or "ax" or "bx" or "cx" or "dx" or "al" or "ah" or "bl" or "bh" or "cl" or "ch" or "dl" or "dh";
            }
        }

        private static bool StateEquals(DecompilationState a, DecompilationState b)
        {
            if (ReferenceEquals(a, b))
                return true;
            if (a == null || b == null)
                return false;

            if (a.RegisterValues.Count != b.RegisterValues.Count)
                return false;
            foreach (var kv in a.RegisterValues)
            {
                if (!b.RegisterValues.TryGetValue(kv.Key, out var bv))
                    return false;
                if (!string.Equals(kv.Value, bv, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            if (a.Stack.Count != b.Stack.Count)
                return false;
            for (var i = 0; i < a.Stack.Count; i++)
            {
                if (!string.Equals(a.Stack[i], b.Stack[i], StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            return true;
        }

        private static DecompilationState JoinStates(DecompilationState a, DecompilationState b)
        {
            if (a == null && b == null)
                return new DecompilationState();
            if (a == null)
                return b.Clone();
            if (b == null)
                return a.Clone();

            var (regs, stack) = JoinStateForTest(a.RegisterValues, a.Stack, b.RegisterValues, b.Stack);
            var merged = new DecompilationState();
            foreach (var kv in regs)
                merged.RegisterValues[kv.Key] = kv.Value;
            merged.Stack.AddRange(stack);
            return merged;
        }

        internal static (Dictionary<string, string> regs, List<string> stack) JoinStateForTest(
            Dictionary<string, string> aRegs,
            List<string> aStack,
            Dictionary<string, string> bRegs,
            List<string> bStack)
        {
            var regs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (aRegs != null && bRegs != null)
            {
                foreach (var kv in aRegs)
                {
                    if (!bRegs.TryGetValue(kv.Key, out var bv))
                        continue;
                    if (string.Equals(kv.Value, bv, StringComparison.OrdinalIgnoreCase))
                        regs[kv.Key] = kv.Value;
                }
            }

            var stack = new List<string>();
            if (aStack != null && bStack != null && aStack.Count == bStack.Count)
            {
                for (var i = 0; i < aStack.Count; i++)
                {
                    stack.Add(string.Equals(aStack[i], bStack[i], StringComparison.OrdinalIgnoreCase) ? aStack[i] : "unk");
                }
            }

            return (regs, stack);
        }

        private static void BuildCFG(ParsedFunction fn, Dictionary<string, string> labelByAddr)
        {
            if (fn == null || fn.Blocks == null || fn.Blocks.Count == 0) return;

            for (int i = 0; i < fn.Blocks.Count; i++)
            {
                var block = fn.Blocks[i];
                var lastLine = block.Lines.LastOrDefault(l => l.Kind == ParsedLineKind.Instruction);
                if (lastLine == null)
                {
                    if (i + 1 < fn.Blocks.Count)
                    {
                        var succ = fn.Blocks[i + 1];
                        block.Successors.Add(succ.Label);
                        if (!succ.Predecessors.Contains(block.Label)) succ.Predecessors.Add(block.Label);
                    }
                    continue;
                }

                var asm = lastLine.Asm.ToLowerInvariant();
                if (IsJccLine(lastLine, out var mn, out var jccTarget))
                {
                    block.LastJumpMnemonic = mn;
                    var targetLabel = labelByAddr.GetValueOrDefault(jccTarget);
                    if (targetLabel != null)
                    {
                        block.Successors.Add(targetLabel);
                        var targetBlock = fn.Blocks.FirstOrDefault(b => b.Label.Equals(targetLabel, StringComparison.OrdinalIgnoreCase));
                        if (targetBlock != null) { if (!targetBlock.Predecessors.Contains(block.Label)) targetBlock.Predecessors.Add(block.Label); }
                    }
                    if (i + 1 < fn.Blocks.Count)
                    {
                        var succ = fn.Blocks[i + 1];
                        block.Successors.Add(succ.Label);
                        if (!succ.Predecessors.Contains(block.Label)) succ.Predecessors.Add(block.Label);
                    }
                }
                else if (asm.StartsWith("jmp", StringComparison.Ordinal))
                {
                    var m = Regex.Match(asm, @"0x(?<addr>[0-9a-f]{1,8})");
                    if (m.Success)
                    {
                        var addr = m.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                        var targetLabel = labelByAddr.GetValueOrDefault(addr);
                        if (targetLabel != null)
                        {
                            block.Successors.Add(targetLabel);
                            var targetBlock = fn.Blocks.FirstOrDefault(b => b.Label.Equals(targetLabel, StringComparison.OrdinalIgnoreCase));
                            if (targetBlock != null) { if (!targetBlock.Predecessors.Contains(block.Label)) targetBlock.Predecessors.Add(block.Label); }
                        }
                    }
                }
                else if (asm.StartsWith("ret", StringComparison.Ordinal))
                {
                    // No successors
                }
                else
                {
                    if (i + 1 < fn.Blocks.Count)
                    {
                        var succ = fn.Blocks[i + 1];
                        block.Successors.Add(succ.Label);
                        if (!succ.Predecessors.Contains(block.Label)) succ.Predecessors.Add(block.Label);
                    }
                }
            }
        }

        private static void InferVariableTypes(ParsedFunction fn)
        {
            if (fn == null) return;
            foreach (var block in fn.Blocks)
            {
                foreach (var line in block.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    
                    var lineText = line.Asm; 
                    var m = Regex.Match(lineText, @"\b(?<size>byte|word|dword|qword)\s+(?:ptr\s+)?\[(?<op>[^\]]+)\]", RegexOptions.IgnoreCase);
                    string inferredType = null;
                    string targetOp = null;

                    if (m.Success)
                    {
                        var size = m.Groups["size"].Value.ToLowerInvariant();
                        targetOp = m.Groups["op"].Value;
                        inferredType = size switch {
                            "byte" => "uint8_t",
                            "word" => "uint16_t",
                            "dword" => "uint32_t",
                            "qword" => "uint64_t",
                            _ => null
                        };
                    }
                    else
                    {
                        // Check for implied sizes: mov [ebp-47h], al
                        var mBare = Regex.Match(lineText, @"\[(?<op>[^\]]+)\]", RegexOptions.IgnoreCase);
                        if (mBare.Success)
                        {
                            targetOp = mBare.Groups["op"].Value;
                        }
                        else
                        {
                            // Bare variables without brackets: mov eax, arg_0
                            var mVar = Regex.Match(lineText, @"\b(?<var>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\b", RegexOptions.IgnoreCase);
                            if (mVar.Success)
                            {
                                targetOp = mVar.Groups["var"].Value;
                            }
                        }

                        if (targetOp != null)
                        {
                            var sz = GetOperandSize(lineText);
                            inferredType = sz switch { 1 => "uint8_t", 2 => "uint16_t", 4 => "uint32_t", _ => null };
                        }
                    }

                    if (inferredType != null && targetOp != null)
                    {
                        var varName = (string)null;

                        // Case 1: already symbolized [local_XX]
                        var mSym = Regex.Match(targetOp.Trim(), @"^(?<var>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
                        if (mSym.Success)
                        {
                            varName = mSym.Groups["var"].Value.ToLowerInvariant();
                        }
                        else
                        {
                            // Case 2: raw ebp index
                            var ebpMatch = Regex.Match(targetOp, @"ebp\s*(?<sign>[\+\-])\s*(?<off>0x[0-9A-Fa-f]+|[0-9]+|(?<hexoff>[0-9A-Fa-f]+)h)", RegexOptions.IgnoreCase);
                            if (ebpMatch.Success) {
                                var sign = ebpMatch.Groups["sign"].Value;
                                var offStr = ebpMatch.Groups["off"].Value;
                                uint off;
                                if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                                    off = Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                                else if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                                    off = Convert.ToUInt32(offStr.Substring(2), 16);
                                else
                                    off = uint.Parse(offStr);
                                
                                if (sign == "-") varName = "local_" + off.ToString("x");
                                else varName = "arg_" + ((off-8)/4).ToString("x");
                            }
                        }

                        if (varName != null)
                        {
                            if (!fn.InferredTypes.TryGetValue(varName, out var existing) || 
                                (existing == "uint8_t" && inferredType != "uint8_t") ||
                                (existing == "uint16_t" && (inferredType == "uint32_t")))
                            {
                                fn.InferredTypes[varName] = inferredType;
                            }
                        }
                    }
                }
            }
        }

        private sealed class PendingFlags
        {
            public string LastCmpLhs;
            public string LastCmpRhs;
            public bool LastWasCmp;

            public string LastTestLhs;
            public string LastTestRhs;
            public bool LastWasTest;

            // Tracks the last INC/DEC target so we can recover simple jz/jnz patterns
            // (ZF after INC/DEC is equivalent to result == 0).
            public string LastIncDecOperand;
            public bool LastWasIncDec;

            // Tracks the last arithmetic op that can set overflow (for jo/jno recovery).
            public bool LastWasArith;
            public string LastArithOp; // add|sub|inc|dec
            public string LastArithA;
            public string LastArithB;

            public string LastEaxAssignment;

            public void Clear(bool targetIsEax = false)
            {
                LastCmpLhs = null;
                LastCmpRhs = null;
                LastWasCmp = false;
                LastTestLhs = null;
                LastTestRhs = null;
                LastWasTest = false;
                LastIncDecOperand = null;
                LastWasIncDec = false;
                LastWasArith = false;
                LastArithOp = null;
                LastArithA = null;
                LastArithB = null;
                if (targetIsEax) LastEaxAssignment = null;
            }

            public void ClearAll()
            {
                Clear(true);
            }
        }

        private static string ExtractProtoFromHeader(List<string> headerLines)
        {
            if (headerLines == null)
                return string.Empty;

            foreach (var l in headerLines)
            {
                var t = l.Trim();
                var m = Regex.Match(t, @"^;\s*PROTO:\s*(?<p>.+?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var proto = m.Groups["p"].Value.Trim();
                    // If it's already a C-like prototype, keep it; else wrap.
                    if (proto.Contains('('))
                    {
                        // Ignore weak prototypes like func_...(arg_0, arg_1) since they lack types.
                        var parenMatch = Regex.Match(proto, @"\((?<args>[^)]*)\)");
                        if (parenMatch.Success)
                        {
                            var argPart = parenMatch.Groups["args"].Value.Trim();
                            if (!string.IsNullOrEmpty(argPart) && Regex.IsMatch(argPart, @"^arg_[0-9A-Fa-f]+(\s*,\s*arg_[0-9A-Fa-f]+)*$", RegexOptions.IgnoreCase))
                            {
                                // it's likely (arg_0, arg_1, ...) with no types. Reject it.
                                continue;
                            }
                        }

                        // Some headers currently emit name-only prototypes like "func_XXXXXXXX()".
                        // Strip disassembler hints like "... (+N)"
                        proto = Regex.Replace(proto, @",?\s*\.\.\.\s*\(\+\d+\)", "");

                        // Normalize to valid C by defaulting the return type to void.
                        var beforeParen = proto.Split('(')[0].Trim();
                        if (!beforeParen.Contains(' '))
                            proto = "void " + proto;

                        // Fix naked args (arg_0, arg_1) => (uint32_t arg_0, uint32_t arg_1)
                        proto = FixNakedArgs(proto);

                        return proto;
                    }
                }
            }

            return string.Empty;
        }

        private static string FixNakedArgs(string proto)
        {
            var m = Regex.Match(proto, @"\((?<args>[^)]*)\)");
            if (!m.Success) return proto;
            var args = m.Groups["args"].Value;
            if (string.IsNullOrWhiteSpace(args) || args.Trim().ToLowerInvariant() == "void") return proto;
            
            var parts = args.Split(',');
            bool allNaked = true;
            for (int i = 0; i < parts.Length; i++)
            {
                var p = parts[i].Trim();
                if (string.IsNullOrEmpty(p)) continue; 
                if (p.Contains(' ')) { allNaked = false; break; }
                if (!p.StartsWith("arg_", StringComparison.OrdinalIgnoreCase)) { allNaked = false; break; }
            }
            
            if (allNaked)
            {
                var newArgs = string.Join(", ", parts.Select(p => "uint32_t " + p.Trim()));
                return proto.Replace("(" + args + ")", "(" + newArgs + ")");
            }
            return proto;
        }

        private static string SanitizeLabel(string label)
        {
            if (string.IsNullOrWhiteSpace(label))
                return "L";

            // Keep it a valid C label: [A-Za-z_][A-Za-z0-9_]*
            var s = Regex.Replace(label, "[^A-Za-z0-9_]", "_");
            if (!char.IsLetter(s[0]) && s[0] != '_')
                s = "L_" + s;
            return s;
        }

        private static ParsedInsOrComment TryParseAsmInstructionLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;

            // Example:
            // 0007E06Bh C6061B          mov byte [ptr_...], 0x1b              ; HINT: ...
            // Pattern: addr 'h' space bytes space asm (trimmed) ';' comment
            var m = Regex.Match(
                line,
                @"^(?<addr>[0-9A-Fa-f]{8})h\s+(?<bytes>[0-9A-Fa-f]+)\s+(?<asm>.+?)\s*(?:;\s*(?<c>.*))?$",
                RegexOptions.None);

            if (!m.Success)
                return null;

            var result = new ParsedInsOrComment
            {
                Kind = ParsedLineKind.Instruction,
                Raw = line,
                AddrHex = m.Groups["addr"].Value.ToUpperInvariant(),
                BytesHex = m.Groups["bytes"].Value.ToUpperInvariant(),
                Asm = m.Groups["asm"].Value.Trim(),
                Comment = (m.Groups["c"].Value ?? string.Empty).Trim()
            };

            var asm = result.Asm;
            var spaceIdx = asm.IndexOfAny(new[] { ' ', '\t' });
            if (spaceIdx > 0)
            {
                result.Mnemonic = asm.Substring(0, spaceIdx).Trim();
                result.Operands = asm.Substring(spaceIdx).Trim();
            }
            else
            {
                result.Mnemonic = asm;
                result.Operands = string.Empty;
            }

            return result;
        }

        private static string TranslateInstructionToPseudoC(
            ParsedInsOrComment ins,
            Dictionary<string, string> labelByAddr,
            PendingFlags pending,
            ParsedFunction fn,
            Dictionary<string, ParsedFunction> functionsByName,
            Dictionary<string, (string proto, int argCount)> otherFunctions,
            DecompilationState state)
        {
            var asm = ins.Asm;
            if (string.IsNullOrWhiteSpace(asm))
                return string.Empty;

            var commentSuffix = (string.IsNullOrWhiteSpace(ins.Comment) ? string.Empty : " // " + ins.Comment) + (string.IsNullOrWhiteSpace(ins.BytesHex) ? string.Empty : $" /* RAW: {ins.BytesHex} */");

            // Split mnemonic and operands.
            var m = Regex.Match(asm, @"^(?<mn>[a-zA-Z]+)\s*(?<ops>.*)$");
            if (!m.Success)
                return "/* " + asm + " */" + commentSuffix;

            var mn = m.Groups["mn"].Value.ToLowerInvariant();
            var ops = m.Groups["ops"].Value.Trim();

            // Heuristic for EAX modification
            bool dstIsEax = false;
            if (mn is "mov" or "lea" or "add" or "sub" or "and" or "or" or "xor" or "shl" or "shr" or "sar")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null && parts.Value.lhs.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn == "shrd")
            {
                var parts = SplitThreeOperands(ops);
                if (parts != null && parts.Value.o1.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn is "inc" or "dec" or "pop")
            {
                if (ops.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn is "imul" or "idiv")
            {
                dstIsEax = true;
            }

            // Track flag-setting ops for the next conditional jump.
            if (mn == "cmp")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    pending.LastWasCmp = true;
                    pending.LastWasTest = false;
                    var lhsSize = GetOperandSize(parts.Value.lhs);
                    var rhsSize = GetOperandSize(parts.Value.rhs);
                    pending.LastCmpLhs = WrapExprForPointerMath(NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false, fn, rhsSize));
                    pending.LastCmpRhs = WrapExprForPointerMath(NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn, lhsSize));
                }
                return "// " + asm + commentSuffix;
            }
            if (mn == "test")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    pending.LastWasTest = true;
                    pending.LastWasCmp = false;
                    var lhsSize = GetOperandSize(parts.Value.lhs);
                    var rhsSize = GetOperandSize(parts.Value.rhs);
                    pending.LastTestLhs = WrapExprForPointerMath(NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false, fn, rhsSize));
                    pending.LastTestRhs = WrapExprForPointerMath(NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn, lhsSize));
                }
                return "// " + asm + commentSuffix;
            }

            if (mn == "rep")
            {
                pending.Clear(dstIsEax);
                var subMn = ops.ToLowerInvariant();
                if (subMn == "movsd") return $"memcpy(__ptr(edi), __ptr(esi), ecx * 4);{commentSuffix}";
                if (subMn == "movsw") return $"memcpy(__ptr(edi), __ptr(esi), ecx * 2);{commentSuffix}";
                if (subMn == "movsb") return $"memcpy(__ptr(edi), __ptr(esi), ecx);{commentSuffix}";
                if (subMn == "stosd") return $"memset_32(edi, eax, ecx);{commentSuffix}";
                if (subMn == "stosw") return $"memset_16(edi, ax, ecx);{commentSuffix}";
                if (subMn == "stosb") return $"memset(__ptr(edi), al, ecx);{commentSuffix}";
            }

            if (mn == "repne")
            {
                pending.Clear(dstIsEax);
                var subMn = ops.ToLowerInvariant();
                if (subMn == "scasb") return $"ecx = strlen_rep(edi, al, ecx);{commentSuffix}";
            }

            if (mn == "imul")
            {
                pending.Clear(dstIsEax);
                var p3 = SplitThreeOperands(ops);
                if (p3 != null)
                {
                    var dst = NormalizeAsmOperandToC(p3.Value.o1, isMemoryWrite: true, fn);
                    var src = NormalizeAsmOperandToC(p3.Value.o2, isMemoryWrite: false, fn);
                    var imm = NormalizeAsmOperandToC(p3.Value.o3, isMemoryWrite: false, fn);

                    pending.LastWasArith = true;
                    pending.LastArithOp = "imul";
                    pending.LastArithA = WrapExprForPointerMath(state.Resolve(src));
                    pending.LastArithB = WrapExprForPointerMath(state.Resolve(imm));

                    return $"{dst} = {src} * {imm};{commentSuffix}";
                }

                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn);
                    var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn);

                    pending.LastWasArith = true;
                    pending.LastArithOp = "imul";
                    pending.LastArithA = WrapExprForPointerMath(state.Resolve(lhs));
                    pending.LastArithB = WrapExprForPointerMath(state.Resolve(rhs));

                    return $"{lhs} *= {rhs};{commentSuffix}";
                }
                else if (!string.IsNullOrWhiteSpace(ops))
                {
                    // Single operand imul: edx:eax = eax * ops
                    var src = NormalizeAsmOperandToC(ops, isMemoryWrite: false, fn);

                    pending.LastWasArith = true;
                    pending.LastArithOp = "imul";
                    pending.LastArithA = WrapExprForPointerMath(state.Resolve("eax"));
                    pending.LastArithB = WrapExprForPointerMath(state.Resolve(src));

                    return $"{{ int64_t res = (int64_t)eax * (int64_t){src}; eax = (uint32_t)res; edx = (uint32_t)(res >> 32); }}{commentSuffix}";
                }
            }

            if (mn == "idiv")
            {
                pending.Clear(dstIsEax);
                if (!string.IsNullOrWhiteSpace(ops))
                {
                    var divisor = NormalizeAsmOperandToC(ops, isMemoryWrite: false, fn);
                    return $"{{ int64_t dividend = ((int64_t)edx << 32) | eax; eax = (uint32_t)(dividend / (int32_t){divisor}); edx = (uint32_t)(dividend % (int32_t){divisor}); }}{commentSuffix}";
                }
            }

            if (mn == "push")
            {
                pending.Clear(dstIsEax);
                var resolved = WrapExprForPointerMath(state.Resolve(NormalizeAsmOperandToC(ops, false, fn)));
                state.Push(resolved);
                return $"// push {resolved};";
            }
            if (mn is "shld" or "shrd")
            {
                var p3 = SplitThreeOperands(ops);
                if (p3 != null)
                {
                    pending.Clear(dstIsEax);
                    var dst = NormalizeAsmOperandToC(p3.Value.o1, isMemoryWrite: true, fn);
                    var src = NormalizeAsmOperandToC(p3.Value.o2, isMemoryWrite: false, fn);
                    var amt = NormalizeAsmOperandToC(p3.Value.o3, isMemoryWrite: false, fn);
                    var op = mn == "shld" ? "<<" : ">>";
                    var inv = mn == "shld" ? ">>" : "<<";
                    return $"{dst} = ({dst} {op} {amt}) | ({src} {inv} (32 - {amt}));{commentSuffix}";
                }
            }

            if (mn.StartsWith("cmov", StringComparison.Ordinal))
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var jcc = "j" + mn.Substring(4);
                    var cond = TryMakeConditionFromPending(jcc, pending);
                    if (!string.IsNullOrWhiteSpace(cond))
                    {
                        var dst = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn);
                        var src = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn);
                        return $"if ({cond}) {dst} = {src};{commentSuffix}";
                    }
                }
            }

            if (mn == "bswap")
            {
                pending.Clear(dstIsEax);
                var dst = NormalizeAsmOperandToC(ops, isMemoryWrite: true, fn);
                return $"{dst} = __builtin_bswap32({dst});{commentSuffix}";
            }

            if (mn == "pop")
            {
                pending.Clear(dstIsEax);
                var lhs = NormalizeAsmOperandToC(ops, true, fn);
                var val = state.Pop();
                state.Set(lhs, val);
                return $"{lhs} = {val};";
            }

            if (mn == "mov")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                var lhsSize = GetOperandSize(parts.Value.lhs);
                var rhsSize = GetOperandSize(parts.Value.rhs);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn, rhsSize);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn, lhsSize);
                
                var resolvedRhs = WrapExprForPointerMath(state.Resolve(rhs));
                state.Set(lhs, resolvedRhs);
                if (lhs == "eax") pending.LastEaxAssignment = resolvedRhs;
                return $"{lhs} = {resolvedRhs};{commentSuffix}";
            }

            if (mn is "movzx" or "movsx")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    pending.Clear(dstIsEax);
                    var lhsSize = GetOperandSize(parts.Value.lhs);
                    var rhsSize = GetOperandSize(parts.Value.rhs);
                    var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn, rhsSize);
                    var rhs = WrapExprForPointerMath(NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn, lhsSize));
                    var cast = mn == "movzx" ? "(uint32_t)" : "(int32_t)";
                    return $"{lhs} = {cast}{rhs};{commentSuffix}";
                }
            }

            if (mn.StartsWith("set", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(ops))
            {
                var jcc = "j" + mn.Substring(3);
                var cond = TryMakeConditionFromPending(jcc, pending);
                if (!string.IsNullOrWhiteSpace(cond))
                {
                    var dst = NormalizeAsmOperandToC(ops, isMemoryWrite: true, fn);
                    return $"{dst} = ({cond}) ? 1 : 0;{commentSuffix}";
                }
            }

            if (mn == "lea")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false, fn);
                
                // For LEA, we want the address of the operand.
                var rhsRaw = parts.Value.rhs;
                var addrExpr = NormalizeLeaRhsToAddressExpr(rhsRaw);
                if (!string.IsNullOrWhiteSpace(addrExpr))
                    return $"{lhs} = (uint32_t)({addrExpr});{commentSuffix}";

                var rhs = NormalizeAsmOperandToC(rhsRaw, isMemoryWrite: false, fn);
                rhs = StripSingleDeref(rhs);
                return $"{lhs} = (uint32_t)({rhs});{commentSuffix}";
            }

            if (mn is "add" or "sub" or "and" or "or" or "xor" or "adc" or "sbb")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);

                var lhsSize = GetOperandSize(parts.Value.lhs);
                var rhsSize = GetOperandSize(parts.Value.rhs);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn, rhsSize);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn, lhsSize);

                var resolvedRhs = WrapExprForPointerMath(state.Resolve(rhs));

                // For overflow-based conditionals (jo/jno), capture the arithmetic inputs.
                // We must do this before we potentially drop register tracking for lhs.
                if (mn is "add" or "sub")
                {
                    pending.LastWasArith = true;
                    pending.LastArithOp = mn;
                    pending.LastArithA = WrapExprForPointerMath(state.Resolve(lhs));
                    pending.LastArithB = resolvedRhs;
                }
                
                if (mn == "xor" && lhs.Equals(rhs, StringComparison.OrdinalIgnoreCase))
                {
                    state.Set(lhs, "0");
                    if (lhs == "eax") pending.LastEaxAssignment = "0";
                    return $"{lhs} = 0;{commentSuffix}";
                }

                // If we are modifying a register, we can't reliably track its value anymore without full math folding.
                if (DecompilationState.IsRegister(lhs)) state.RegisterValues.Remove(lhs);

                var op = mn switch
                {
                    "add" => "+=",
                    "sub" => "-=",
                    "and" => "&=",
                    "or" => "|=",
                    "xor" => "^=",
                    "adc" => "+= (carry +",
                    "sbb" => "-= (carry +",
                    _ => "="
                };
                var suffix = (mn is "adc" or "sbb") ? ")" : "";
                return $"{lhs} {op} {resolvedRhs}{suffix};{commentSuffix}";
            }

            if (mn is "shl" or "shr" or "sar")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true, fn);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn);
                var op = mn == "shl" ? "<<=" : ">>=";
                // If rhs is constant > 31, mask it to avoid C undefined behavior (matching x86 behavior)
                if (rhs.StartsWith("0x") || int.TryParse(rhs, out _))
                {
                    long val = 0;
                    bool parsed = false;
                    if (rhs.StartsWith("0x")) { try { val = Convert.ToInt64(rhs, 16); parsed = true; } catch {} }
                    else { parsed = int.TryParse(rhs, out int iv); val = iv; }

                    if (parsed && val >= 32)
                    {
                        var masked = val % 32;
                        return $"{lhs} {op} {masked}; // masked from {rhs} to match x86 behavior{commentSuffix}";
                    }
                }
                return $"{lhs} {op} {rhs};{commentSuffix}";
            }

            if (mn == "bt" || mn == "bts" || mn == "btr")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var val = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: mn != "bt", fn);
                    var bit = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false, fn);
                    if (mn == "bt") return $"// test bit: ({val} >> {bit}) & 1{commentSuffix}";
                    var op = mn == "bts" ? "|=" : "&=";
                    var bitVal = $"(1 << {bit})";
                    if (mn == "btr") bitVal = "~" + bitVal;
                    return $"{val} {op} {bitVal};{commentSuffix}";
                }
            }

            if (mn == "out")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var port = NormalizeAsmOperandToC(parts.Value.lhs, false, fn);
                    var val = NormalizeAsmOperandToC(parts.Value.rhs, false, fn);
                    return $"__out({port}, {val});{commentSuffix}";
                }
            }
            if (mn == "in")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var dst = NormalizeAsmOperandToC(parts.Value.lhs, true, fn);
                    var port = NormalizeAsmOperandToC(parts.Value.rhs, false, fn);
                    return $"{dst} = __in({port});{commentSuffix}";
                }
            }

            if (mn == "neg")
            {
                pending.Clear(dstIsEax);
                if (string.IsNullOrWhiteSpace(ops)) return "// " + asm;
                var opnd = NormalizeAsmOperandToC(ops, isMemoryWrite: true, fn);
                return $"{opnd} = -{opnd};{commentSuffix}";
            }

            if (mn == "inc" || mn == "dec")
            {
                pending.Clear(dstIsEax);
                if (string.IsNullOrWhiteSpace(ops))
                    return "/* " + asm + " */" + commentSuffix;

                var opnd = NormalizeAsmOperandToC(ops, isMemoryWrite: true, fn);
                pending.LastIncDecOperand = opnd;
                pending.LastWasIncDec = true;

                pending.LastWasArith = true;
                pending.LastArithOp = mn;
                pending.LastArithA = WrapExprForPointerMath(state.Resolve(opnd));
                pending.LastArithB = "1";

                return mn == "inc" ? $"({opnd})++;{commentSuffix}" : $"({opnd})--;{commentSuffix}";
            }

            if (mn == "not")
            {
                pending.Clear(dstIsEax);
                if (string.IsNullOrWhiteSpace(ops)) return "// " + asm;
                var opnd = NormalizeAsmOperandToC(ops, isMemoryWrite: true, fn);
                return $"{opnd} = ~{opnd};{commentSuffix}";
            }

            if (mn == "cdq" || mn == "cltd") return $"edx = (uint32_t)((int32_t)eax >> 31);{commentSuffix}";
            // Avoid relying on sub-register locals (ax/al/ah); compute via masks on eax/edx.
            if (mn == "cwde") return $"eax = (uint32_t)(int16_t)(eax & 0xFFFFu);{commentSuffix}";
            if (mn == "cwd") return $"edx = (edx & 0xFFFF0000u) | (uint16_t)(((int16_t)(eax & 0xFFFFu)) >> 15);{commentSuffix}";
            if (mn == "cbw") return $"eax = (eax & 0xFFFF0000u) | (uint16_t)(int8_t)(eax & 0xFFu);{commentSuffix}";

            if (mn == "call")
            {
                pending.Clear(dstIsEax);
                state.ClearVolatile();
                var target = ResolveCallTarget(ops, labelByAddr);
                int argCount = 0;
                if (functionsByName.TryGetValue(target, out var targetFn)) argCount = targetFn.ArgCount;
                else if (otherFunctions.TryGetValue(target, out var other)) argCount = other.argCount;

                var argsList = new List<string>();
                for (int i = 0; i < argCount; i++) argsList.Add(WrapExprForPointerMath(state.Pop()));
                argsList.Reverse();

                var argsStrs = argsList.Count > 0 ? string.Join(", ", argsList) : "";
                return $"{target}({argsStrs});{commentSuffix}";
            }

            if (mn == "ret")
            {
                var retVal = "";
                if (fn.RetType != "void")
                {
                    if (pending.LastEaxAssignment != null) retVal = " " + pending.LastEaxAssignment;
                    else if (ins.Comment != null && ins.Comment.Contains("RET: eax", StringComparison.OrdinalIgnoreCase))
                        retVal = " eax";
                    else if (ins.Comment != null && (ins.Comment.Contains("RET: ax", StringComparison.OrdinalIgnoreCase) || ins.Comment.Contains("RET: al", StringComparison.OrdinalIgnoreCase)))
                        retVal = " eax"; // simplified
                    else
                        retVal = " eax"; // Fallback for non-void functions
                }

                pending.Clear(true);
                return $"return{retVal};{commentSuffix}";
            }

            if (mn == "jmp")
            {
                pending.Clear(dstIsEax);
                var target = ResolveTarget(ops, labelByAddr);
                // Heuristic: if jumping to another function, it's a tail call.
                if (target.StartsWith("func_", StringComparison.OrdinalIgnoreCase))
                {
                    int argCount = 0;
                    string retType = "uint32_t";
                    if (functionsByName.TryGetValue(target, out var targetFn)) { argCount = targetFn.ArgCount; retType = targetFn.RetType; }
                    else if (otherFunctions.TryGetValue(target, out var other)) { argCount = other.argCount; }

                    var args = string.Join(", ", Enumerable.Repeat("0", argCount));
                    if (retType != "void")
                        return $"return {target}({args});{commentSuffix}";
                    return $"{target}({args}); return;{commentSuffix}";
                }
                return $"goto {target};{commentSuffix}";
            }

            if (mn == "loop")
            {
                pending.Clear(dstIsEax);
                var target = ResolveTarget(ops, labelByAddr);
                return $"if (--ecx != 0) goto {target};{commentSuffix}";
            }

            if (mn == "cld") return $"// direction = forward;{commentSuffix}";
            if (mn == "std") return $"// direction = backward;{commentSuffix}";
            if (mn == "leave")
            {
                pending.ClearAll();
                return $"esp = ebp; ebp = pop();{commentSuffix}";
            }

            if (mn.StartsWith("f", StringComparison.Ordinal))
            {
                // FPU instruction: prefix with FPU to make it stand out.
                return $"// FPU: {asm}{commentSuffix}";
            }

            if (mn == "int")
            {
                pending.Clear(dstIsEax);
                var mInt = Regex.Match(ops, @"^(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|[0-9]+)\b");
                if (mInt.Success)
                {
                    var imm = mInt.Groups["imm"].Value;
                    int intNo = -1;
                    try
                    {
                        if (imm.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) intNo = Convert.ToInt32(imm.Substring(2), 16);
                        else if (imm.EndsWith("h", StringComparison.OrdinalIgnoreCase)) intNo = Convert.ToInt32(imm.TrimEnd('h', 'H'), 16);
                        else intNo = int.Parse(imm);
                    }
                    catch { intNo = -1; }

                    if (intNo >= 0 && intNo <= 0xFF)
                        return $"DOS_INT(0x{intNo:X2});{commentSuffix}";
                }

                return "// " + asm + commentSuffix;
            }

            if (IsJcc(mn))
            {
                var target = ResolveTarget(ops, labelByAddr);
                var cond = TryMakeConditionFromPending(mn, pending);
                pending.Clear(dstIsEax);

                if (!string.IsNullOrWhiteSpace(cond))
                    return $"if ({cond}) goto {target};{commentSuffix}";

                return $"if (0 /* unknown: {mn} */) goto {target};{commentSuffix}";
            }

            // Default: keep as comment.
            pending.Clear(dstIsEax);
            return "// " + asm + commentSuffix;
        }

        private static int GetOperandSize(string t)
        {
            if (string.IsNullOrEmpty(t)) return 0;
            t = t.ToLowerInvariant();

            if (t.Contains("byte") || Regex.IsMatch(t, @"\b(al|ah|bl|bh|cl|ch|dl|dh)\b")) return 1;
            if (t.Contains("word") || Regex.IsMatch(t, @"\b(ax|bx|cx|dx|si|di|bp|sp)\b"))
            {
                if (t.Contains("dword")) return 4;
                return 2;
            }
            if (t.Contains("dword") || Regex.IsMatch(t, @"\be(ax|bx|cx|dx|si|di|bp|sp)\b")) return 4;

            return 0; // Unknown
        }

        private static string NormalizeAsmOperandToC(string op, bool isMemoryWrite, ParsedFunction fn, int sizeOverride = 0)
        {
            if (string.IsNullOrWhiteSpace(op))
                return string.Empty;

            var t = op.Trim();

            // Normalize common symbol casing (C identifiers are case-sensitive).
            t = Regex.Replace(
                t,
                @"\b(?<pre>(?:flags|g|ptr|s|p|func|loc|bb)_)(?<addr>[0-9A-Fa-f]{8})\b",
                m => m.Groups["pre"].Value.ToLowerInvariant() + m.Groups["addr"].Value.ToUpperInvariant(),
                RegexOptions.IgnoreCase);

            // Treat g_XXXXXXXX as a numeric linear address literal.
            // Memory access is done via G(addr) elsewhere in the emitter.
            t = Regex.Replace(
                t,
                @"\bg_(?<addr>[0-9A-Fa-f]{8})\b",
                m => $"0x{m.Groups["addr"].Value.ToUpperInvariant()}u",
                RegexOptions.IgnoreCase);

            // Some fixup rewriting can accidentally concatenate a symbol and a trailing byte (e.g. s_000E0792c1).
            // Interpret this as pointer arithmetic on the symbol address.
            t = Regex.Replace(
                t,
                @"\b(?<sym>[ps]_[0-9A-Fa-f]{8})(?<tail>[0-9A-Fa-f]{1,2})\b",
                m => $"((uintptr_t){m.Groups["sym"].Value}+0x{m.Groups["tail"].Value})",
                RegexOptions.IgnoreCase);

            // Normalize field offsets.
            t = Regex.Replace(t, @"\bfield_(?<off>[0-9A-Fa-f]+)\b", m => "field_" + m.Groups["off"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);

            // Normalize arg/local names without underscore.
            t = Regex.Replace(t, @"\barg(?<n>[0-9A-Fa-f]+)\b", m => "arg_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);
            t = Regex.Replace(t, @"\blocal(?<n>[0-9A-Fa-f]+)\b", m => "local_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);

            // Normalize pointer-to-stack aliases.
            t = Regex.Replace(t, @"\bptr_local_(?<n>[0-9A-Fa-f]+)\b", m => "ptr_local_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);
            t = Regex.Replace(t, @"\bptr_arg_(?<n>[0-9A-Fa-f]+)\b", m => "ptr_arg_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);

            // Normalize VARALIAS-style names to a consistent case.
            t = Regex.Replace(t, @"\bout_(?<n>[A-Za-z0-9]+)\b", m => "out_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);
            t = Regex.Replace(t, @"\bopt_(?<n>[A-Za-z0-9]+)\b", m => "opt_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);

            // Normalize any 'this' token to our global storage name.
            t = Regex.Replace(t, @"\bthis\b", "_this", RegexOptions.IgnoreCase);

            // Replace any hex literal or symbolized address with its string/global name/func name.
            // IMPORTANT: do not rewrite immediate constants into g_XXXXXXXX identifiers; that breaks
            // compares like `cmp ..., 0x4000` (and reintroduces g_ after we normalize it to 0x...).
            t = Regex.Replace(t, @"\b(?:0x|[psg]_)?(?<hex>[0-9A-Fa-f]{4,16})h?\b", m => {
                var val = m.Groups["hex"].Value;
                if (_x86Registers.Contains(val)) return m.Value;

                // If the literal is wider than 32-bit in text form (e.g. 0x000E0792C1),
                // only use the low 32-bit part for symbol lookup to avoid partial replacement.
                var low = val.Length > 8 ? val.Substring(val.Length - 8) : val;
                var hex = low.ToUpperInvariant().PadLeft(8, '0');
                if (_addrToString.TryGetValue(hex, out var s)) return $"(uintptr_t){s}";
                // Only map to a g_ symbol if the matched token itself was g_...
                // (Otherwise this would rewrite plain constants into undeclared identifiers.)
                if (m.Value.StartsWith("g_", StringComparison.OrdinalIgnoreCase) && _addrToGlobal.TryGetValue(hex, out var g)) return g;
                return m.Value;
            }, RegexOptions.IgnoreCase);

            // Normalize argX/localX...

            // Already looks like a C-ish deref; leave it.
            if (t.StartsWith("*", StringComparison.Ordinal))
                return t;

            // Handle local/arg variables directly if they are inside brackets [local_XX]
            // The disassembler often emits these as [local_XX] or [arg_X] (or sometimes [argX] without underscore)
            var varMatch = Regex.Match(t, @"^\[(?<var>local_?[0-9A-Fa-f]+|arg_?[0-9A-Fa-f]+)\]$", RegexOptions.IgnoreCase);
            if (varMatch.Success)
            {
                var varName = varMatch.Groups["var"].Value.ToLowerInvariant();
                if (varName.StartsWith("arg") && !varName.StartsWith("arg_")) varName = "arg_" + varName.Substring(3);
                if (varName.StartsWith("local") && !varName.StartsWith("local_")) varName = "local_" + varName.Substring(5);
                
                var tyMatch = sizeOverride switch { 1 => "uint8_t", 2 => "uint16_t", _ => "uint32_t" };
                if (fn.InferredTypes.TryGetValue(varName, out var inferred) && inferred == tyMatch)
                    return varName;
                if (!fn.InferredTypes.ContainsKey(varName)) return varName;
                return $"*({tyMatch}*)&({varName})";
            }

            // Sized var access: dword [local_XX]
            var sizedVar = Regex.Match(t, @"^(?<sz>byte|word|dword|qword)\s+(?:ptr\s+)?\[(?<var>local_?[0-9A-Fa-f]+|arg_?[0-9A-Fa-f]+)\]$", RegexOptions.IgnoreCase);
            if (sizedVar.Success)
            {
                var sz = sizedVar.Groups["sz"].Value.ToLowerInvariant();
                var varName = sizedVar.Groups["var"].Value.ToLowerInvariant();
                if (varName.StartsWith("arg") && !varName.StartsWith("arg_")) varName = "arg_" + varName.Substring(3);
                if (varName.StartsWith("local") && !varName.StartsWith("local_")) varName = "local_" + varName.Substring(5);

                var tySizedVar = sz switch { "byte" => "uint8_t", "word" => "uint16_t", "dword" => "uint32_t", "qword" => "uint64_t", _ => "uint32_t" };
                if (fn.InferredTypes.TryGetValue(varName, out var inferred) && inferred == tySizedVar)
                    return varName;
                return $"*({tySizedVar}*)&({varName})";
            }

            // byte/word/dword/qword [expr]  (optionally with 'ptr')
            var sized = Regex.Match(
                t,
                @"^(?<sz>byte|word|dword|qword)\s+(?:ptr\s+)?\[(?<expr>.+)\]$",
                RegexOptions.IgnoreCase);

            if (sized.Success)
            {
                var sz = sized.Groups["sz"].Value.ToLowerInvariant();
                var expr = sized.Groups["expr"].Value.Trim();
                // If the interior expression is a variable, it's just the variable.
                if (Regex.IsMatch(expr, @"^(local_?[0-9A-Fa-f]+|arg_?[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase))
                {
                    var varName = expr.ToLowerInvariant();
                    if (varName.StartsWith("arg") && !varName.StartsWith("arg_")) varName = "arg_" + varName.Substring(3);
                    if (varName.StartsWith("local") && !varName.StartsWith("local_")) varName = "local_" + varName.Substring(5);
                    return varName;
                }

                // Handle ebp-based operands in [ebp-XX] form
                var ebpMatch = Regex.Match(expr, @"^ebp\s*(?<sign>[\+\-])\s*(?<off>0x[0-9A-Fa-f]+|[0-9]+|(?<hexoff>[0-9A-Fa-f]+)h)$", RegexOptions.IgnoreCase);
                if (ebpMatch.Success)
                {
                    var sign = ebpMatch.Groups["sign"].Value;
                    var offStr = ebpMatch.Groups["off"].Value;
                    uint off;
                    if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                        off = Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                    else if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        off = Convert.ToUInt32(offStr.Substring(2), 16);
                    else
                        off = uint.Parse(offStr);

                    var tyEbp = sz switch { "byte" => "uint8_t", "word" => "uint16_t", "dword" => "uint32_t", "qword" => "uint64_t", _ => "uint32_t" };
                    if (sign == "-") 
                    {
                        var varName = $"local_{off:x}".ToLowerInvariant();
                        if (fn.InferredTypes.TryGetValue(varName, out var inferred) && inferred == tyEbp)
                            return varName;
                        return $"*({tyEbp}*)&({varName})";
                    }
                    if (off >= 8) return $"arg_{(off - 8) / 4:x}".ToLowerInvariant();
                }

                var ty = sz switch
                {
                    "byte" => "uint8_t",
                    "word" => "uint16_t",
                    "dword" => "uint32_t",
                    "qword" => "uint64_t",
                    _ => "uint32_t"
                };
                return $"*({ty}*)__ptr((uint32_t)({WrapExprForPointerMath(expr)}))";
            }

            // Bare [expr] => assume dword in 32-bit mode unless sizeOverride set.
            var bare = Regex.Match(t, @"^\[(?<expr>.+?)\]$", RegexOptions.None);
            if (bare.Success)
            {
                var expr = bare.Groups["expr"].Value.Trim();
                if (Regex.IsMatch(expr, @"^(local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase))
                    return expr.ToLowerInvariant();

                // Handle bare ebp-based operands if the rewriter missed them (e.g. in hints)
                var ebpMatch = Regex.Match(expr, @"^ebp\s*(?<sign>[\+\-])\s*(?<off>0x[0-9A-Fa-f]+|[0-9]+|(?<hexoff>[0-9A-Fa-f]+)h)$", RegexOptions.IgnoreCase);
                if (ebpMatch.Success)
                {
                    var sign = ebpMatch.Groups["sign"].Value;
                    var offStr = ebpMatch.Groups["off"].Value;
                    uint off;
                    if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                        off = Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                    else if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        off = Convert.ToUInt32(offStr.Substring(2), 16);
                    else
                        off = uint.Parse(offStr);

                    var tyBareEbp = sizeOverride switch { 1 => "uint8_t", 2 => "uint16_t", _ => "uint32_t" };
                    if (sign == "-") 
                    {
                        var varName = $"local_{off:x}".ToLowerInvariant();
                        if (fn.InferredTypes.TryGetValue(varName, out var inferred) && inferred == tyBareEbp)
                            return varName;
                        return $"*({tyBareEbp}*)&({varName})";
                    }
                    if (off >= 8) return $"arg_{(off - 8) / 4:x}".ToLowerInvariant();
                }

                string type = "uint32_t";
                if (sizeOverride == 1) type = "uint8_t";
                else if (sizeOverride == 2) type = "uint16_t";

                return $"*({type}*)__ptr((uint32_t)({WrapExprForPointerMath(expr)}))";
            }

            // Handle hex literals that might be strings or globals
            var hexMatch = Regex.Match(t, @"^(?:0x)?(?<hex>[0-9A-Fa-f]{4,8})h?$", RegexOptions.IgnoreCase);
            if (hexMatch.Success)
            {
                var hex = hexMatch.Groups["hex"].Value.ToUpperInvariant().PadLeft(8, '0');
                if (_addrToString.TryGetValue(hex, out var s)) return s;
                // If this hex literal maps to a known global address, emit it as a numeric linear address.
                // We intentionally don't emit thousands of g_XXXXXXXX declarations (to keep Watcom from OOMing),
                // so returning a bare g_XXXXXXXX here would trigger E1011 (symbol not declared).
                if (_addrToGlobal.TryGetValue(hex, out _)) return $"0x{hex}u";
            }

            if ((t.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase) || t.StartsWith("s_", StringComparison.OrdinalIgnoreCase)))
            {
                var ptrMatch = Regex.Match(t, @"[ps]_(?<addr>[0-9A-Fa-f]{8})", RegexOptions.IgnoreCase);
                if (ptrMatch.Success)
                {
                    var addr = ptrMatch.Groups["addr"].Value.ToUpperInvariant();
                    if (_addrToString.TryGetValue(addr, out var s)) return s;
                }
            }

            // If a symbolized global/ptr token appears as a bare value (not dereferenced),
            // treat it as an address. This avoids invalid C like `ebp = g_XXXXXXXX;` where
            // g_XXXXXXXX is declared as a byte array placeholder.
            var symAddr = Regex.Match(t, @"^(?:g_|ptr_|s_)(?<addr>[0-9A-Fa-f]{8})$", RegexOptions.IgnoreCase);
            if (symAddr.Success)
            {
                var addr = symAddr.Groups["addr"].Value.ToUpperInvariant();
                return $"0x{addr}u";
            }

            return t;
        }

        internal static string NormalizeLeaRhsToAddressExpr(string rhsRaw)
        {
            if (string.IsNullOrWhiteSpace(rhsRaw))
                return null;

            // Examples:
            //   [ebp-0x10]
            //   dword ptr [ebp+0x8]
            //   [local_10]
            //   [arg_2]
            // Return a stable variable-based address expression when possible.

            var s = rhsRaw.Trim();
            s = Regex.Replace(s, @"^(?:byte|word|dword|qword)\s+(?:ptr\s+)?", "", RegexOptions.IgnoreCase).Trim();

            var bracket = Regex.Match(s, @"^\[(?<expr>.+)\]$", RegexOptions.None);
            if (bracket.Success)
                s = bracket.Groups["expr"].Value.Trim();

            // Normalize arg/local tokens without underscore.
            s = Regex.Replace(s, @"\barg(?<n>[0-9A-Fa-f]+)\b", m => "arg_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);
            s = Regex.Replace(s, @"\blocal(?<n>[0-9A-Fa-f]+)\b", m => "local_" + m.Groups["n"].Value.ToLowerInvariant(), RegexOptions.IgnoreCase);

            var localTok = Regex.Match(s, @"^local_(?<off>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (localTok.Success)
                return "&local_" + localTok.Groups["off"].Value.ToLowerInvariant();

            var argTok = Regex.Match(s, @"^arg_(?<idx>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (argTok.Success)
                return "&arg_" + argTok.Groups["idx"].Value.ToLowerInvariant();

            var ebp = Regex.Match(s, @"^ebp\s*(?<sign>[\+\-])\s*(?<off>0x[0-9A-Fa-f]+|[0-9]+|(?<hexoff>[0-9A-Fa-f]+)h)$", RegexOptions.IgnoreCase);
            if (ebp.Success)
            {
                var sign = ebp.Groups["sign"].Value;
                var offStr = ebp.Groups["off"].Value;
                uint off;
                if (offStr.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                    off = Convert.ToUInt32(offStr.TrimEnd('h', 'H'), 16);
                else if (offStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    off = Convert.ToUInt32(offStr.Substring(2), 16);
                else
                    off = uint.Parse(offStr);

                if (sign == "-")
                    return $"&local_{off:x}";

                // Args: [ebp+8] is arg_0. Only map clean dword slots.
                if (off >= 8 && ((off - 8) % 4u) == 0)
                    return $"&arg_{((off - 8) / 4u):x}";
            }

            return null;
        }

        private static string WrapExprForPointerMath(string expr)
        {
            if (string.IsNullOrWhiteSpace(expr))
                return expr;

            // Remove segment prefixes like cs:
            expr = Regex.Replace(expr, @"\b(cs|ds|es|fs|gs|ss):", "", RegexOptions.IgnoreCase);

            // Replace hex with g_ symbols if known
            expr = Regex.Replace(expr, @"\b(?:0x)?(?<hex>[0-9A-Fa-f]{5,8})h?\b", m => {
                var h = m.Groups["hex"].Value.TrimStart('0');
                if (h.Length < 4) h = m.Groups["hex"].Value; // keep some padding if it was short
                var hex = m.Groups["hex"].Value.ToUpperInvariant().PadLeft(8, '0');
                if (_addrToGlobal.TryGetValue(hex, out var g)) return g;
                return m.Value;
            }, RegexOptions.IgnoreCase);

            // Change dot to plus for macros like ptr.field
            expr = expr.Replace(".", " + ");

            // Convert symbolized address tokens (g_/ptr_/s_) to numeric guest linear addresses.
            // Avoid conversion when taking address-of or indexing an array placeholder.
            expr = Regex.Replace(expr, @"(?<!&\s*)\b(?:g_|ptr_|s_)(?<addr>[0-9A-Fa-f]{8})\b(?!\s*\[)",
                m => $"0x{m.Groups["addr"].Value.ToUpperInvariant()}u", RegexOptions.IgnoreCase);

            // Keep it numeric: all guest memory accesses go through __ptr(addr).
            var regMatch = Regex.Match(expr, @"^(?<reg>eax|ebx|ecx|edx|esi|edi|ebp|esp)(?<rest>[\+\-].+)$", RegexOptions.IgnoreCase);
            if (regMatch.Success)
            {
                return $"({regMatch.Groups["reg"].Value} {regMatch.Groups["rest"].Value})";
            }

            return expr;
        }

        private static string StripSingleDeref(string expr)
        {
            if (string.IsNullOrWhiteSpace(expr))
                return expr;

            var trimmed = expr.Trim();

            // *(uint32_t*)(something)  =>  (something)
            var m = Regex.Match(trimmed, @"^\*\([^\)]*\)\((?<inner>.*)\)$");
            if (m.Success)
                return m.Groups["inner"].Value.Trim();

            // *(uint32_t*)__ptr((uint32_t)(addr))  =>  addr
            var m2 = Regex.Match(trimmed, @"^\*\([^\)]*\)\s*__ptr\((?<inner>.*)\)\s*$");
            if (m2.Success)
            {
                var inner = m2.Groups["inner"].Value.Trim();

                // Peel common casts/paren wrappers: (uint32_t)(X) or ((uint32_t)(X))
                for (int i = 0; i < 2; i++)
                {
                    var mc = Regex.Match(inner, @"^\(?\s*\(uint32_t\)\s*\((?<a>.*)\)\s*\)?$", RegexOptions.IgnoreCase);
                    if (!mc.Success) break;
                    inner = mc.Groups["a"].Value.Trim();
                }

                // Also peel one outer paren pair.
                var mp = Regex.Match(inner, @"^\((?<a>.*)\)$");
                if (mp.Success) inner = mp.Groups["a"].Value.Trim();
                return inner;
            }

            return expr;
        }

        private static void MarkLoopHeaders(ParsedFunction fn, Dictionary<string, string> labelByAddr)
        {
            if (fn == null) return;
            var seenLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            foreach (var block in fn.Blocks)
            {
                seenLabels.Add(block.Label);
                
                // Check last line for jumps
                if (block.Lines.Count > 0)
                {
                    var last = block.Lines.Last();
                    if (last.Kind == ParsedLineKind.Instruction)
                    {
                        var asm = last.Asm.ToLowerInvariant();
                        string target = null;
                        
                        if (asm.StartsWith("jmp", StringComparison.Ordinal) || IsJcc(asm.Split(' ')[0]))
                        {
                            var match = Regex.Match(asm, @"0x(?<addr>[0-9A-Fa-f]+)");
                            if (match.Success)
                            {
                                var addr = match.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                                target = labelByAddr.GetValueOrDefault(addr);
                            }
                        }
                        
                        if (target != null && seenLabels.Contains(target))
                        {
                            // Back-edge!
                            fn.LoopHeaders.Add(target);
                        }
                    }
                }
            }
        }

        private static string NegateCondition(string cond)
        {
            if (string.IsNullOrEmpty(cond)) return "!(unknown)";
            if (cond.Contains("==")) return cond.Replace("==", "!=");
            if (cond.Contains("!=")) return cond.Replace("!=", "==");
            if (cond.Contains("> ")) return cond.Replace("> ", "<= ");
            if (cond.Contains("< ")) return cond.Replace("< ", ">= ");
            if (cond.Contains(">= ")) return cond.Replace(">= ", "< ");
            if (cond.Contains("<= ")) return cond.Replace("<= ", "> ");
            return "!(" + cond + ")";
        }

        private static bool IsJcc(string mn)
        {
            return mn is "jz" or "jnz" or "je" or "jne" or "jg" or "jge" or "jl" or "jle" or "ja" or "jae" or "jb" or "jbe" or "jo" or "jno" or "js" or "jns";
        }

        internal static string MakeConditionFromPendingForTest(
            string jcc,
            bool lastWasCmp,
            string cmpLhs,
            string cmpRhs,
            bool lastWasTest,
            string testLhs,
            string testRhs,
            bool lastWasIncDec,
            string incDecOperand,
            bool lastWasArith,
            string arithOp,
            string arithA,
            string arithB)
        {
            if (string.IsNullOrWhiteSpace(jcc))
                return string.Empty;

            if (lastWasCmp && !string.IsNullOrWhiteSpace(cmpLhs))
            {
                var a = cmpLhs;
                var b = cmpRhs;
                return jcc switch
                {
                    "je" or "jz" => $"{a} == {b}",
                    "jne" or "jnz" => $"{a} != {b}",
                    "jl" => $"(int32_t){a} < (int32_t){b}",
                    "jle" => $"(int32_t){a} <= (int32_t){b}",
                    "jg" => $"(int32_t){a} > (int32_t){b}",
                    "jge" => $"(int32_t){a} >= (int32_t){b}",
                    "js" => $"((int32_t)({a}) - (int32_t)({b})) < 0",
                    "jns" => $"((int32_t)({a}) - (int32_t)({b})) >= 0",
                    // Unsigned comparisons (best-effort; keep explicit cast to show intent).
                    "jb" => $"(uint32_t){a} < (uint32_t){b}",
                    "jbe" => $"(uint32_t){a} <= (uint32_t){b}",
                    "ja" => $"(uint32_t){a} > (uint32_t){b}",
                    "jae" => $"(uint32_t){a} >= (uint32_t){b}",
                    _ => string.Empty
                };
            }

            if (lastWasTest && !string.IsNullOrWhiteSpace(testLhs))
            {
                var a = testLhs;
                var b = testRhs;

                // Simple case: test reg, reg => check if reg is 0, negative, etc.
                if (a.Equals(b, StringComparison.OrdinalIgnoreCase))
                {
                    return jcc switch
                    {
                        "je" or "jz" => $"{a} == 0",
                        "jne" or "jnz" => $"{a} != 0",
                        "js" => $"(int32_t){a} < 0",
                        "jns" => $"(int32_t){a} >= 0",
                        "jg" => $"(int32_t){a} > 0",
                        "jge" => $"(int32_t){a} >= 0",
                        "jl" => $"(int32_t){a} < 0",
                        "jle" => $"(int32_t){a} <= 0",
                        _ => string.Empty
                    };
                }

                if (jcc is "je" or "jz")
                    return $"({a} & {b}) == 0";
                if (jcc is "jne" or "jnz")
                    return $"({a} & {b}) != 0";
            }

            // Heuristic: INC/DEC affects ZF based on the result being zero.
            if (lastWasIncDec && !string.IsNullOrWhiteSpace(incDecOperand))
            {
                var x = incDecOperand;
                return jcc switch
                {
                    "je" or "jz" => $"{x} == 0",
                    "jne" or "jnz" => $"{x} != 0",
                    _ => string.Empty
                };
            }

            // Overflow (OF) recovery for jo/jno after add/sub/inc/dec.
            // Use int64-based check to avoid relying on signed overflow UB.
            if (lastWasArith && (jcc is "jo" or "jno") && !string.IsNullOrWhiteSpace(arithA) && !string.IsNullOrWhiteSpace(arithB))
            {
                string expr = string.Empty;
                if (arithOp is "add" or "inc")
                {
                    expr = $"(((int64_t)(int32_t)({arithA}) + (int64_t)(int32_t)({arithB})) > 0x7fffffffLL) || (((int64_t)(int32_t)({arithA}) + (int64_t)(int32_t)({arithB})) < (-0x80000000LL))";
                }
                else if (arithOp is "sub" or "dec")
                {
                    expr = $"(((int64_t)(int32_t)({arithA}) - (int64_t)(int32_t)({arithB})) > 0x7fffffffLL) || (((int64_t)(int32_t)({arithA}) - (int64_t)(int32_t)({arithB})) < (-0x80000000LL))";
                }
                else if (arithOp is "imul")
                {
                    expr = $"(((int64_t)(int32_t)({arithA}) * (int64_t)(int32_t)({arithB})) > 0x7fffffffLL) || (((int64_t)(int32_t)({arithA}) * (int64_t)(int32_t)({arithB})) < (-0x80000000LL))";
                }

                if (!string.IsNullOrWhiteSpace(expr))
                    return jcc == "jo" ? expr : $"!({expr})";
            }

            return string.Empty;
        }

        private static string TryMakeConditionFromPending(string jcc, PendingFlags pending)
        {
            if (pending == null)
                return string.Empty;

            return MakeConditionFromPendingForTest(
                jcc,
                pending.LastWasCmp,
                pending.LastCmpLhs,
                pending.LastCmpRhs,
                pending.LastWasTest,
                pending.LastTestLhs,
                pending.LastTestRhs,
                pending.LastWasIncDec,
                pending.LastIncDecOperand,
                pending.LastWasArith,
                pending.LastArithOp,
                pending.LastArithA,
                pending.LastArithB);
        }

        private static (string o1, string o2, string o3)? SplitThreeOperands(string ops)
        {
            if (string.IsNullOrWhiteSpace(ops))
                return null;

            var items = new List<string>();
            var depth = 0;
            var start = 0;
            for (var i = 0; i < ops.Length; i++)
            {
                var c = ops[i];
                if (c == '[') depth++;
                else if (c == ']') depth = Math.Max(0, depth - 1);
                else if (c == ',' && depth == 0)
                {
                    items.Add(ops.Substring(start, i - start).Trim());
                    start = i + 1;
                }
            }
            items.Add(ops.Substring(start).Trim());

            if (items.Count == 3)
                return (items[0], items[1], items[2]);

            return null;
        }

        private static List<string> OptimizeStatements(List<string> lines)
        {
            if (lines == null || lines.Count < 1) return lines;

            var res = new List<string>();
            for (var i = 0; i < lines.Count; i++)
            {
                var cur = lines[i];

                // Peephole: redundant x = x;
                var mSelf = Regex.Match(cur, @"^\s*([^;/\s]+)\s*=\s*\1\s*;", RegexOptions.IgnoreCase);
                if (mSelf.Success && !cur.Contains("(")) // Avoid matches with side effects or complex types for now
                {
                    continue; 
                }

                // Peephole 1: reg1 = var; var2 = reg1;  => var2 = var;
                // Only if reg1 is one of the scratch registers (eax, etc) and not used immediately again.
                if (i + 1 < lines.Count)
                {
                    var m1 = Regex.Match(cur, @"^(?<reg>e[a-z]{2})\s*=\s*(?<src>[^;/\s]+);.*$");
                    var next = lines[i + 1];
                    var m2 = Regex.Match(next, @"^(?<dst>[^;/\s]+)\s*=\s*(?<reg2>e[a-z]{2});.*$");

                    if (m1.Success && m2.Success)
                    {
                        var reg1 = m1.Groups["reg"].Value;
                        var reg2 = m2.Groups["reg2"].Value;
                        var src = m1.Groups["src"].Value;
                        var dst = m2.Groups["dst"].Value;

                        if (reg1.Equals(reg2, StringComparison.OrdinalIgnoreCase) && 
                            !src.Equals(dst, StringComparison.OrdinalIgnoreCase))
                        {
                            // Avoid optimizing if src or dst are complex pointer derefs for now 
                            if (!src.Contains("(") && !dst.Contains("("))
                            {
                                res.Add($"{dst} = {src}; // optimized: {cur.TrimEnd()} + {next.TrimStart()}");
                                i++; // Skip next
                                continue;
                            }
                        }
                    }
                }

                // Peephole 3: Combine consecutive math on same var? e.g. add esp, 4; add esp, 8
                if (i + 1 < lines.Count)
                {
                    var mAdd1 = Regex.Match(cur, @"^(?<var>[a-z_0-9]+)\s*(?<op>\+=|-=)\s*(?<val>0x[0-9A-Fa-f]+|[0-9]+);", RegexOptions.IgnoreCase);
                    var next = lines[i + 1];
                    var mAdd2 = Regex.Match(next, @"^(?<var2>[a-z_0-9]+)\s*(?<op2>\+=|-=)\s*(?<val2>0x[0-9A-Fa-f]+|[0-9]+);", RegexOptions.IgnoreCase);
                    if (mAdd1.Success && mAdd2.Success)
                    {
                        var v1 = mAdd1.Groups["var"].Value;
                        var v2 = mAdd2.Groups["var2"].Value;
                        if (v1.Equals(v2, StringComparison.OrdinalIgnoreCase))
                        {
                            try {
                                var o1 = mAdd1.Groups["op"].Value;
                                var o2 = mAdd2.Groups["op2"].Value;
                                var val1Str = mAdd1.Groups["val"].Value;
                                var val2Str = mAdd2.Groups["val2"].Value;
                                long val1 = val1Str.StartsWith("0x") ? Convert.ToInt64(val1Str, 16) : long.Parse(val1Str);
                                long val2 = val2Str.StartsWith("0x") ? Convert.ToInt64(val2Str, 16) : long.Parse(val2Str);
                                if (o1 == "-=") val1 = -val1;
                                if (o2 == "-=") val2 = -val2;
                                long total = val1 + val2;
                                if (total == 0) { i++; continue; }
                                string newOp = total < 0 ? "-=" : "+=";
                                res.Add($"{v1} {newOp} 0x{Math.Abs(total):x}; // combined math");
                                i++;
                                continue;
                            } catch { }
                        }
                    }
                }

                // Peephole 4: Detect x = x + 1; or x = x - 1; and use ++/--
                var mMath1 = Regex.Match(cur, @"^(?<var>[a-z_0-9]+)\s*=\s*\k<var>\s*(?<op>\+|-)\s*1;.*$", RegexOptions.IgnoreCase);
                if (mMath1.Success)
                {
                    var v = mMath1.Groups["var"].Value;
                    var op = mMath1.Groups["op"].Value == "+" ? "++" : "--";
                    res.Add($"{v}{op}; // simplified math");
                    continue;
                }

                res.Add(cur);
            }

            return res;
        }

        private static void SimulateInstructionForState(ParsedInsOrComment ins, DecompilationState state, ParsedFunction fn)
        {
            var asm = ins.Asm;
            if (string.IsNullOrWhiteSpace(asm)) return;

            var m = Regex.Match(asm, @"^(?<mn>[a-zA-Z]+)\s*(?<ops>.*)$");
            if (!m.Success) return;

            var mn = m.Groups["mn"].Value.ToLowerInvariant();
            var ops = m.Groups["ops"].Value.Trim();

            if (mn == "push")
            {
                state.Push(state.Resolve(NormalizeAsmOperandToC(ops, false, fn)));
            }
            else if (mn == "pop")
            {
                state.Pop();
                if (ops.Equals("eax", StringComparison.OrdinalIgnoreCase)) state.Clear(true);
                else state.Set(ops, "pop()");
            }
            else if (mn == "mov")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    state.Set(parts.Value.lhs, state.Resolve(NormalizeAsmOperandToC(parts.Value.rhs, false, fn)));
                }
            }
            else if (mn == "lea")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var addrExpr = NormalizeLeaRhsToAddressExpr(parts.Value.rhs);
                    if (!string.IsNullOrWhiteSpace(addrExpr))
                        state.Set(parts.Value.lhs, addrExpr);
                    else
                        state.Set(parts.Value.lhs, state.Resolve(NormalizeAsmOperandToC(parts.Value.rhs, false, fn)));
                }
            }
            else if (mn == "add" || mn == "sub" || mn == "xor" || mn == "or" || mn == "and" || mn == "shl" || mn == "shr" || mn == "sar")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    if (parts.Value.lhs.Equals("esp", StringComparison.OrdinalIgnoreCase))
                    {
                        if (mn == "add") {
                            try {
                                var val = NormalizeAsmOperandToC(parts.Value.rhs, false, fn);
                                int bytes = 0;
                                if (val.StartsWith("0x")) bytes = Convert.ToInt32(val, 16);
                                else int.TryParse(val, out bytes);
                                for (int i = 0; i < bytes / 4 && state.Stack.Count > 0; i++) state.Pop();
                            } catch {}
                        }
                    }
                    else {
                        state.Clear(parts.Value.lhs.Equals("eax", StringComparison.OrdinalIgnoreCase));
                    }
                }
            }
            else if (mn == "call")
            {
                state.ClearVolatile();
                // Pop arguments if possible
                var callMatch = Regex.Match(asm, @"0x(?<addr>[0-9A-Fa-f]{8})");
                if (callMatch.Success) {
                    // We don't have the dictionary here easily, but we can skip
                }
            }
        }

        private static (string lhs, string rhs)? SplitTwoOperands(string ops)
        {
            if (string.IsNullOrWhiteSpace(ops))
                return null;

            // Split on the first comma not inside brackets.
            var depth = 0;
            for (var i = 0; i < ops.Length; i++)
            {
                var c = ops[i];
                if (c == '[')
                    depth++;
                else if (c == ']')
                    depth = Math.Max(0, depth - 1);
                else if (c == ',' && depth == 0)
                {
                    var lhs = ops.Substring(0, i).Trim();
                    var rhs = ops.Substring(i + 1).Trim();
                    if (string.IsNullOrWhiteSpace(lhs) || string.IsNullOrWhiteSpace(rhs))
                        return null;
                    return (lhs, rhs);
                }
            }

            return null;
        }

        private static void IdentifySimpleStructures(ParsedFunction fn)
        {
            // Identify structures
            foreach (var b in fn.Blocks)
            {
                var p = new PendingFlags();
                foreach (var line in b.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    var asm = line.Asm.ToLowerInvariant();
                    if (asm.StartsWith("cmp "))
                    {
                        var ops = asm.Substring(4).Trim();
                        var parts = SplitTwoOperands(ops);
                        if (parts != null)
                        {
                            p.LastWasCmp = true; p.LastWasTest = false;
                            p.LastCmpLhs = NormalizeAsmOperandToC(parts.Value.lhs, false, fn);
                            p.LastCmpRhs = NormalizeAsmOperandToC(parts.Value.rhs, false, fn);
                        }
                    }
                    else if (asm.StartsWith("test "))
                    {
                        var ops = asm.Substring(5).Trim();
                        var parts = SplitTwoOperands(ops);
                        if (parts != null)
                        {
                            p.LastWasTest = true; p.LastWasCmp = false;
                            p.LastTestLhs = NormalizeAsmOperandToC(parts.Value.lhs, false, fn);
                            p.LastTestRhs = NormalizeAsmOperandToC(parts.Value.rhs, false, fn);
                        }
                    }
                }

                if (b.Successors.Count == 2)
                {
                    var sJump = b.Successors[0]; // Usually the jump target
                    var sFall = b.Successors[1]; // Usually the fallthrough

                    var bJump = fn.Blocks.FirstOrDefault(x => x.Label.Equals(sJump, StringComparison.OrdinalIgnoreCase));
                    var bFall = fn.Blocks.FirstOrDefault(x => x.Label.Equals(sFall, StringComparison.OrdinalIgnoreCase));

                    if (bJump != null && bFall != null)
                    {
                        // Triangle (If-Then): A -> B, C; B -> C
                        if (bJump.Successors.Count == 1 && bJump.Successors[0].Equals(sFall, StringComparison.OrdinalIgnoreCase))
                        {
                            b.StructuredType = "if-then";
                            var cond = TryMakeConditionFromPending(b.LastJumpMnemonic, p);
                            b.StructuredCondition = !string.IsNullOrEmpty(cond) ? NegateCondition(cond) : NegateAsmCondition(b.LastJumpMnemonic);
                            b.StructuredFollow = sFall;
                        }
                        else if (bFall.Successors.Count == 1 && bFall.Successors[0].Equals(sJump, StringComparison.OrdinalIgnoreCase))
                        {
                            b.StructuredType = "if-then";
                            var cond = TryMakeConditionFromPending(b.LastJumpMnemonic, p);
                            b.StructuredCondition = !string.IsNullOrEmpty(cond) ? cond : b.LastJumpMnemonic;
                            b.StructuredFollow = sJump;
                        }
                        // Diamond (If-Then-Else): A -> B, C; B -> D; C -> D
                        else if (bJump.Successors.Count == 1 && bFall.Successors.Count == 1 &&
                                 bJump.Successors[0].Equals(bFall.Successors[0], StringComparison.OrdinalIgnoreCase))
                        {
                            var sFollow = bJump.Successors[0];
                            b.StructuredType = "diamond-header";
                            var cond = TryMakeConditionFromPending(b.LastJumpMnemonic, p);
                            b.StructuredCondition = !string.IsNullOrEmpty(cond) ? NegateCondition(cond) : NegateAsmCondition(b.LastJumpMnemonic);
                            b.StructuredFollow = sFall; // The 'else' block is the first follow
                            b.SecondaryFollow = sFollow;
                        }
                    }
                }
                // While(1) detect: block ends in jmp to itself
                if (b.Successors.Count == 1 && b.Successors[0].Equals(b.Label, StringComparison.OrdinalIgnoreCase))
                {
                    b.StructuredType = "while-true";
                }
            }
        }

        private static string NegateAsmCondition(string jccMn)
        {
            if (string.IsNullOrEmpty(jccMn)) return "!(unknown)";
            switch (jccMn.ToLowerInvariant())
            {
                case "jz": return "jnz";
                case "je": return "jne";
                case "jnz": return "jz";
                case "jne": return "je";
                case "ja": return "jbe";
                case "jae": return "jb";
                case "jb": return "jae";
                case "jbe": return "ja";
                case "jg": return "jle";
                case "jge": return "jl";
                case "jl": return "jge";
                case "jle": return "jg";
                default: return "!" + jccMn;
            }
        }
    }
}
