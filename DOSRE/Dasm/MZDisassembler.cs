using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using DOSRE.Enums;
using SharpDisasm;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Minimal disassembler for DOS MZ ("old" EXE) format.
    ///
    /// This file intentionally only contains the orchestration / main loop.
    /// Implementation details live in the other MZDisassembler.*.cs partials.
    /// </summary>
    public static partial class MZDisassembler
    {
        public static bool TryDisassembleToString(
            string inputFile,
            bool mzFull,
            int? mzBytesLimit,
            bool mzInsights,
            out string output,
            out string error)
        {
            return TryDisassembleToString(inputFile, mzFull, mzBytesLimit, mzInsights, EnumToolchainHint.None, out output, out error);
        }

        public static bool TryDisassembleToString(
            string inputFile,
            bool mzFull,
            int? mzBytesLimit,
            bool mzInsights,
            EnumToolchainHint toolchainHint,
            out string output,
            out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(inputFile) || !File.Exists(inputFile))
            {
                error = "Input file does not exist";
                return false;
            }

            var fileBytes = File.ReadAllBytes(inputFile);
            if (!TryParseMZHeader(fileBytes, out var h))
            {
                error = "MZ header not found";
                return false;
            }

            // If this looks like an NE/LE/PE stub, we intentionally fail for now.
            if (h.e_lfanew >= 0x40 && h.e_lfanew + 2 < fileBytes.Length)
            {
                var sig0 = fileBytes[h.e_lfanew];
                var sig1 = fileBytes[h.e_lfanew + 1];
                if ((sig0 == (byte)'N' && sig1 == (byte)'E') ||
                    (sig0 == (byte)'L' && sig1 == (byte)'E') ||
                    (sig0 == (byte)'P' && sig1 == (byte)'E'))
                {
                    error = "Has extended header (NE/LE/PE)";
                    return false;
                }
            }

            var fileSize = ComputeMzFileSizeBytes(h, fileBytes.Length);
            if (fileSize <= 0 || fileSize > fileBytes.Length)
                fileSize = fileBytes.Length;

            var headerBytes = h.e_cparhdr * 16;
            if (headerBytes <= 0 || headerBytes >= fileSize)
            {
                error = "Invalid MZ header size";
                return false;
            }

            var moduleSize = fileSize - headerBytes;
            var module = new byte[moduleSize];
            Buffer.BlockCopy(fileBytes, headerBytes, module, 0, moduleSize);

            var entryLinear = (uint)((h.e_cs << 4) + h.e_ip);
            if (entryLinear >= module.Length)
            {
                error = $"Invalid entrypoint CS:IP {h.e_cs:X4}:{h.e_ip:X4} (linear 0x{entryLinear:X})";
                return false;
            }

            var maxBytes = mzBytesLimit ?? (mzFull ? int.MaxValue : 64 * 1024);
            var codeLen = Math.Min(module.Length - (int)entryLinear, maxBytes);
            if (codeLen <= 0)
            {
                error = "No bytes to disassemble";
                return false;
            }

            var code = new byte[codeLen];
            Buffer.BlockCopy(module, (int)entryLinear, code, 0, codeLen);

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (MZ / DOS)");
            sb.AppendLine($"; Entry: CS:IP {h.e_cs:X4}:{h.e_ip:X4} (linear 0x{entryLinear:X})");

            if (toolchainHint != EnumToolchainHint.None)
            {
                var markers = FindToolchainMarkers(module, toolchainHint, 12);
                if (markers.Count > 0)
                {
                    sb.AppendLine("; Toolchain markers");
                    foreach (var m in markers.OrderBy(m => m.Offset))
                        sb.AppendLine($"; 0x{m.Offset:X}  {m.Text}");
                }
            }
            sb.AppendLine(";");

            Dictionary<uint, string> stringSyms = null;
            Dictionary<uint, string> stringPrev = null;
            if (mzInsights)
                ScanStrings(module, out stringSyms, out stringPrev);

            if (mzInsights && stringSyms?.Count > 0)
            {
                sb.AppendLine("; Strings");
                foreach (var kvp in stringSyms.OrderBy(k => k.Key).Take(256))
                {
                    var prev = stringPrev != null && stringPrev.TryGetValue(kvp.Key, out var p) ? p : "";
                    sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X} ; \"{prev}\"");
                }
                sb.AppendLine(";");
            }

            var startOffset = entryLinear;
            var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_16, startOffset, true);
            var instructions = dis.Disassemble().ToList();
            var insIndexByAddr = instructions.Select((ins, idx) => new { ins, idx }).ToDictionary(x => (uint)x.ins.Offset, x => x.idx);

            var functionStarts = new HashSet<uint> { entryLinear };
            var labelTargets = new HashSet<uint>();
            var callXrefs = new Dictionary<uint, List<uint>>();
            var jumpXrefs = new Dictionary<uint, List<uint>>();

            if (mzInsights)
            {
                for (var i = 0; i + 1 < instructions.Count; i++)
                {
                    var b0 = instructions[i].Bytes;
                    var b1 = instructions[i + 1].Bytes;
                    if (b0?.Length >= 1 && b0[0] == 0x55 && b1?.Length >= 2 && b1[0] == 0x8B && b1[1] == 0xEC)
                        functionStarts.Add((uint)instructions[i].Offset);
                }
            }

            foreach (var ins in instructions)
            {
                if (TryGetRelativeBranchTarget16(ins, out var target, out var isCall))
                {
                    if (target >= startOffset && target < startOffset + (uint)codeLen)
                    {
                        if (isCall)
                        {
                            functionStarts.Add(target);
                            if (!callXrefs.TryGetValue(target, out var callers))
                                callXrefs[target] = callers = new List<uint>();
                            callers.Add((uint)ins.Offset);
                        }
                        else
                        {
                            labelTargets.Add(target);
                            if (!jumpXrefs.TryGetValue(target, out var sources))
                                jumpXrefs[target] = sources = new List<uint>();
                            sources.Add((uint)ins.Offset);
                        }
                    }
                }
            }

            var orderedFunctionStarts = functionStarts.OrderBy(x => x).ToList();
            var funcInfos = new Dictionary<uint, FunctionInfo>();
            for (var i = 0; i < orderedFunctionStarts.Count; i++)
            {
                var fstart = orderedFunctionStarts[i];
                if (!insIndexByAddr.TryGetValue(fstart, out var startIdx))
                    continue;

                var endIdx = instructions.Count;
                if (i + 1 < orderedFunctionStarts.Count && insIndexByAddr.TryGetValue(orderedFunctionStarts[i + 1], out var nextIdx))
                    endIdx = nextIdx;

                var info = new FunctionInfo { Start = fstart, StartIndex = startIdx, EndIndex = endIdx };
                TryAnalyzeFunctionMetaData(info, instructions);
                funcInfos[fstart] = info;
            }

            sb.AppendLine("; OFFSET BYTES DISASSEMBLY");
            sb.AppendLine(";-------------------------------------------");

            byte? lastAh = null, lastAl = null;
            ushort? lastAxImm = null, lastBxImm = null, lastCxImm = null, lastDxImm = null;
            ushort? lastSiImm = null, lastDiImm = null, lastBpImm = null, lastDsImm = null, lastEsImm = null;

            sbyte? lastBxBpDisp8 = null;
            var bpFrameWords = new Dictionary<sbyte, ushort>();
            var bpFrameSyms = new Dictionary<sbyte, string>();
            var esIsSs = false;
            var esSavedAsSsDepth = 0;
            string lastLdsSiBaseSym = null;

            FunctionInfo currentFunc = null;

            byte? lastInt21GetVectorInt = null;
            int lastInt21GetVectorIndex = -1;

            for (var i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;

                if (mzInsights && functionStarts.Contains(addr))
                {
                    sb.AppendLine();
                    sb.AppendLine($"func_{addr:X5}:");
                    if (callXrefs.TryGetValue(addr, out var callers))
                        sb.AppendLine($"; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X}"))}");

                    currentFunc = funcInfos.TryGetValue(addr, out var fi) ? fi : null;

                    lastAh = lastAl = null;
                    lastAxImm = lastBxImm = lastCxImm = lastDxImm = lastSiImm = lastDiImm = lastBpImm = lastDsImm = lastEsImm = null;
                    lastBxBpDisp8 = null;
                    bpFrameWords.Clear();
                    bpFrameSyms.Clear();
                    esIsSs = false;
                    esSavedAsSsDepth = 0;
                    lastLdsSiBaseSym = null;

                    if (mzInsights && currentFunc != null)
                    {
                        if (currentFunc.HasFrame)
                        {
                            static string FormatArgs(SortedSet<int> argOffsets)
                            {
                                if (argOffsets == null || argOffsets.Count == 0)
                                    return string.Empty;

                                var groups = argOffsets
                                    .Where(o => o >= 4)
                                    .GroupBy(o => (o - 4) / 2)
                                    .OrderBy(g => g.Key);

                                var parts = new List<string>();
                                foreach (var g in groups)
                                {
                                    var offs = g.Distinct().OrderBy(x => x).ToArray();
                                    var even = offs.FirstOrDefault(x => (x & 1) == 0);
                                    var hasEven = offs.Any(x => (x & 1) == 0);
                                    var hasOdd = offs.Any(x => (x & 1) == 1);

                                    if (hasEven && hasOdd)
                                        parts.Add($"arg{g.Key}@+0x{even:X} (word)");
                                    else if (hasEven)
                                        parts.Add($"arg{g.Key}@+0x{even:X}");
                                    else
                                        parts.Add($"arg{g.Key}_hi@+0x{offs[0]:X}");
                                }

                                return string.Join(", ", parts);
                            }

                            static string FormatLocals(SortedSet<int> localOffsets, int maxToShow)
                            {
                                if (localOffsets == null || localOffsets.Count == 0)
                                    return string.Empty;

                                // Group local byte offsets into word-ish labels when both bytes appear.
                                var groups = localOffsets
                                    .Where(o => o >= 2)
                                    .GroupBy(o => o / 2)
                                    .OrderBy(g => g.Key)
                                    .ToList();

                                var parts = new List<string>();
                                foreach (var g in groups)
                                {
                                    var offs = g.Distinct().OrderBy(x => x).ToArray();
                                    var even = offs.FirstOrDefault(x => (x & 1) == 0);
                                    var hasEven = offs.Any(x => (x & 1) == 0);
                                    var hasOdd = offs.Any(x => (x & 1) == 1);

                                    if (hasEven && hasOdd)
                                        parts.Add($"local_0x{even:X} (word)");
                                    else
                                        parts.Add($"local_0x{offs[0]:X}");
                                }

                                if (parts.Count <= maxToShow)
                                    return string.Join(", ", parts);

                                var head = string.Join(", ", parts.Take(maxToShow));
                                return $"{head}, ... (+{parts.Count - maxToShow} more)";
                            }

                            if (currentFunc.ArgOffsets.Count > 0)
                            {
                                var args = FormatArgs(currentFunc.ArgOffsets);
                                if (!string.IsNullOrEmpty(args))
                                    sb.AppendLine($"; ARGS: {args}");
                            }

                            if (currentFunc.LocalOffsets.Count > 0)
                            {
                                var locals = FormatLocals(currentFunc.LocalOffsets, maxToShow: 40);
                                if (!string.IsNullOrEmpty(locals))
                                    sb.AppendLine($"; LOCALS: {locals}");
                            }
                        }
                        if (currentFunc.RetPopBytes > 0)
                            sb.AppendLine($"; PROTO?: callee pops {currentFunc.RetPopBytes} bytes (~{currentFunc.RetPopBytes / 2} args)");

                        var summary = TrySummarizeFunction(currentFunc, instructions);
                        if (!string.IsNullOrEmpty(summary))
                            sb.AppendLine($"; SUMMARY: {summary}");
                    }
                }
                else if (mzInsights && labelTargets.Contains(addr))
                {
                    sb.AppendLine($"loc_{addr:X5}:");
                    if (jumpXrefs.TryGetValue(addr, out var sources))
                        sb.AppendLine($"; XREF: jumped from {string.Join(", ", sources.Distinct().OrderBy(x => x).Select(x => $"0x{x:X}"))}");
                }

                var bytes = BitConverter.ToString(ins.Bytes).Replace("-", "");
                var insText = ins.ToString();

                if (mzInsights)
                {
                    UpdateStackState(
                        ins, i, instructions,
                        ref esIsSs, ref esSavedAsSsDepth, ref lastBxBpDisp8, ref lastLdsSiBaseSym,
                        bpFrameWords, bpFrameSyms,
                        lastAxImm, lastCxImm, lastDxImm, lastBxImm, lastSiImm, lastDiImm,
                        lastDsImm, lastEsImm);

                    var hInd = TryGetIndirectCallHint(ins, instructions, i);
                    if (!string.IsNullOrEmpty(hInd)) insText += $" ; {hInd}";

                    var hPack = TryGetPackedNibbleShiftHint(instructions, i);
                    if (!string.IsNullOrEmpty(hPack)) insText += $" ; {hPack}";

                    var hHigh = TryGetHigherLevelHint(
                        instructions, i,
                        lastAh, lastAl,
                        lastAxImm, lastBxImm, lastCxImm, lastDxImm,
                        lastSiImm, lastDiImm,
                        lastBpImm,
                        lastDsImm, lastEsImm);
                    if (!string.IsNullOrEmpty(hHigh)) insText += $" ; {hHigh}";

                    UpdateSimpleDosState(
                        ins,
                        ref lastAh, ref lastAl,
                        ref lastAxImm, ref lastBxImm, ref lastCxImm, ref lastDxImm,
                        ref lastSiImm, ref lastDiImm,
                        ref lastBpImm, ref lastDsImm, ref lastEsImm);
                }

                if (mzInsights && TryGetRelativeBranchTarget16(ins, out var target2, out var isCall2))
                {
                    if (target2 >= startOffset && target2 < startOffset + (uint)codeLen)
                        insText += $" ; {(isCall2 ? "call" : "jmp")} {(isCall2 ? $"func_{target2:X5}" : $"loc_{target2:X5}")}";
                }

                if (mzInsights && stringSyms?.Count > 0)
                {
                    insText = RewriteKnownStringLiteral(insText, stringSyms);
                    var inline = TryInlineStringPreview(insText, stringPrev);
                    if (!string.IsNullOrEmpty(inline)) insText += $" ; {inline}";
                }

                if (mzInsights && currentFunc?.HasFrame == true)
                    insText = RewriteBpFrameOperands(insText, currentFunc);

                if (mzInsights)
                {
                    var axHint = lastAxImm ?? (lastAh.HasValue && lastAl.HasValue ? (ushort?)((lastAh.Value << 8) | lastAl.Value) : null);
                    var intHint = TryDecodeInterruptHint(
                        ins,
                        lastAh, lastAl,
                        axHint,
                        lastBxImm, lastCxImm, lastDxImm, lastSiImm, lastDiImm,
                        lastBpImm,
                        lastDsImm, lastEsImm,
                        stringSyms, stringPrev,
                        module);
                    if (!string.IsNullOrEmpty(intHint)) insText += $" ; {intHint}";

                    // Heuristic: INT 21h hook/chaining detection.
                    // If we see AH=35h (get vector) for INT xx, then shortly after AH=25h (set vector) for the same INT xx,
                    // it's often a TSR/hook capturing the old handler and installing a new one.
                    if (ins.Bytes?.Length >= 2 && ins.Bytes[0] == 0xCD && ins.Bytes[1] == 0x21)
                    {
                        if (lastAh == 0x35 && lastAl.HasValue)
                        {
                            lastInt21GetVectorInt = lastAl.Value;
                            lastInt21GetVectorIndex = i;
                        }

                        if (lastAh == 0x25 && lastAl.HasValue && lastInt21GetVectorInt.HasValue)
                        {
                            if (lastAl.Value == lastInt21GetVectorInt.Value && lastInt21GetVectorIndex >= 0 && (i - lastInt21GetVectorIndex) <= 50)
                            {
                                insText += $" ; HOOK? captured old INT {lastAl.Value:X2}h vector earlier (ES:BX)";
                            }
                        }
                    }

                    if (ins.Bytes?.Length >= 2 && ins.Bytes[0] == 0xCD && ins.Bytes[1] == 0x21 && lastAh == 0x4B)
                    {
                        var pbHint = TryDecodeExecParamBlockFromStack(lastBxBpDisp8, esIsSs, bpFrameWords, bpFrameSyms, module);
                        if (!string.IsNullOrEmpty(pbHint)) insText += $" ; {pbHint}";
                    }
                }

                sb.AppendLine($"{addr:X5}h {bytes.PadRight(16)} {insText}");
            }

            output = sb.ToString();
            return true;
        }
    }
}
