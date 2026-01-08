using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Analysis;
using DOSRE.Enums;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Minimal disassembler for DOS MZ ("old" EXE) format.
    ///
    /// This is intentionally lightweight and aimed at small utilities / game helpers.
    /// It disassembles 16-bit x86 starting at CS:IP entrypoint within the load module.
    ///
    /// Best-effort insights:
    /// - function/label discovery from relative call/jump targets
    /// - simple prologue detection (push bp; mov bp, sp)
    /// - lightweight string scan over the load module
    /// </summary>
    public static class MZDisassembler
    {
        private sealed class FunctionInfo
        {
            public uint Start;
            public int StartIndex;
            public int EndIndex;
            public bool HasFrame;
            public SortedSet<int> ArgOffsets = new SortedSet<int>();
            public SortedSet<int> LocalOffsets = new SortedSet<int>();
            public int? RetPopBytes;
        }

        private sealed class MZHeader
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            public uint e_lfanew;
        }

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

            // If there is an extended header pointer and it points to a known format, let other pipelines handle it.
            if (h.e_lfanew >= 0x40 && h.e_lfanew + 2 < fileBytes.Length)
            {
                var sig0 = fileBytes[h.e_lfanew];
                var sig1 = fileBytes[h.e_lfanew + 1];
                if ((sig0 == (byte)'N' && sig1 == (byte)'E') || (sig0 == (byte)'L' && sig1 == (byte)'E') || (sig0 == (byte)'P' && sig1 == (byte)'E'))
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

            var codeStart = (int)entryLinear;
            var codeLen = module.Length - codeStart;
            if (!mzFull)
            {
                var defaultLimit = 64 * 1024;
                codeLen = Math.Min(codeLen, mzBytesLimit ?? defaultLimit);
            }
            else if (mzBytesLimit.HasValue)
            {
                codeLen = Math.Min(codeLen, mzBytesLimit.Value);
            }

            if (codeLen <= 0)
            {
                error = "No bytes to disassemble";
                return false;
            }

            var code = new byte[codeLen];
            Buffer.BlockCopy(module, codeStart, code, 0, codeLen);

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (MZ / DOS)");
            sb.AppendLine($"; FileSize: {fileSize}  Header: {headerBytes}  Module: {module.Length}");
            sb.AppendLine($"; Entry: CS:IP {h.e_cs:X4}:{h.e_ip:X4} (linear 0x{entryLinear:X})");
            sb.AppendLine($"; Stack: SS:SP {h.e_ss:X4}:{h.e_sp:X4}");
            if (mzFull)
                sb.AppendLine("; MZ mode: FULL (disassemble from entry to end of module)");
            else
                sb.AppendLine($"; MZ mode: LIMIT {codeLen} bytes");
            if (mzInsights)
                sb.AppendLine("; NOTE: MZ insights enabled (best-effort labels/strings)");

            if (toolchainHint != EnumToolchainHint.None)
            {
                sb.AppendLine($"; Toolchain hint: {toolchainHint}");

                var markers = FindToolchainMarkers(module, toolchainHint, 12);
                if (markers.Count > 0)
                {
                    sb.AppendLine("; Toolchain markers (best-effort)");
                    foreach (var m in markers.OrderBy(m => m.Offset))
                        sb.AppendLine($"; 0x{m.Offset:X}  {m.Text}");
                }
                else
                {
                    sb.AppendLine("; Toolchain markers (best-effort): none found");
                }
            }
            sb.AppendLine(";");

            Dictionary<uint, string> stringSyms = null;
            Dictionary<uint, string> stringPrev = null;
            if (mzInsights)
                ScanStrings(module, out stringSyms, out stringPrev);

            if (mzInsights && stringSyms != null && stringSyms.Count > 0)
            {
                sb.AppendLine("; Strings (best-effort)");
                foreach (var kvp in stringSyms.OrderBy(k => k.Key).Take(256))
                {
                    var prev = stringPrev != null && stringPrev.TryGetValue(kvp.Key, out var p) ? p : string.Empty;
                    if (!string.IsNullOrEmpty(prev))
                        sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X} ; \"{prev}\"");
                    else
                        sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X}");
                }
                if (stringSyms.Count > 256)
                    sb.AppendLine($"; (strings truncated: {stringSyms.Count} total)");
                sb.AppendLine(";");
            }

            var startOffset = entryLinear;
            var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_16, startOffset, true);
            var instructions = dis.Disassemble().ToList();

            var insIndexByAddr = new Dictionary<uint, int>(instructions.Count);
            for (var i = 0; i < instructions.Count; i++)
                insIndexByAddr[(uint)instructions[i].Offset] = i;

            var functionStarts = new HashSet<uint>();
            var labelTargets = new HashSet<uint>();
            var callXrefs = new Dictionary<uint, List<uint>>();
            var jumpXrefs = new Dictionary<uint, List<uint>>();

            functionStarts.Add((uint)entryLinear);

            if (mzInsights)
            {
                // Detect classic 16-bit prologues: push bp; mov bp, sp
                for (var i = 0; i + 1 < instructions.Count; i++)
                {
                    var b0 = instructions[i].Bytes;
                    var b1 = instructions[i + 1].Bytes;
                    if (b0 != null && b0.Length >= 1 && b0[0] == 0x55 && b1 != null && b1.Length >= 2 && b1[0] == 0x8B && b1[1] == 0xEC)
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

            // Build per-function metadata (best-effort)
            var funcInfos = new Dictionary<uint, FunctionInfo>();
            var orderedFuncStarts = functionStarts.OrderBy(x => x).ToList();
            for (var fi = 0; fi < orderedFuncStarts.Count; fi++)
            {
                var fstart = orderedFuncStarts[fi];
                if (!insIndexByAddr.TryGetValue(fstart, out var startIdx))
                    continue;

                var endIdx = instructions.Count;
                if (fi + 1 < orderedFuncStarts.Count && insIndexByAddr.TryGetValue(orderedFuncStarts[fi + 1], out var nextIdx))
                    endIdx = nextIdx;

                var info = new FunctionInfo { Start = fstart, StartIndex = startIdx, EndIndex = endIdx };

                // detect frame + args/locals
                for (var i = startIdx; i < endIdx; i++)
                {
                    var ins = instructions[i];
                    var b = ins.Bytes;

                    if (!info.HasFrame)
                    {
                        // mov bp, sp: 8B EC
                        if (b != null && b.Length >= 2 && b[0] == 0x8B && b[1] == 0xEC)
                            info.HasFrame = true;
                    }

                    // ret imm16: C2 iw, far ret imm16: CA iw
                    if (b != null && b.Length >= 3 && (b[0] == 0xC2 || b[0] == 0xCA))
                    {
                        if (!info.RetPopBytes.HasValue)
                            info.RetPopBytes = (b[1] | (b[2] << 8));
                    }

                    if (!info.HasFrame)
                        continue;

                    var text = ins.ToString();

                    // args: [bp+0xNN]
                    foreach (Match m in Regex.Matches(text, @"\[bp\+0x(?<hex>[0-9a-fA-F]+)\]"))
                    {
                        var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                        if (off >= 4 && off <= 0x80)
                            info.ArgOffsets.Add(off);
                    }
                    foreach (Match m in Regex.Matches(text, @"\[bp\+(?<dec>\d+)\]"))
                    {
                        var off = int.Parse(m.Groups["dec"].Value);
                        if (off >= 4 && off <= 0x80)
                            info.ArgOffsets.Add(off);
                    }

                    // locals: [bp-0xNN]
                    foreach (Match m in Regex.Matches(text, @"\[bp\-0x(?<hex>[0-9a-fA-F]+)\]"))
                    {
                        var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                        if (off >= 2 && off <= 0x200)
                            info.LocalOffsets.Add(off);
                    }
                    foreach (Match m in Regex.Matches(text, @"\[bp\-(?<dec>\d+)\]"))
                    {
                        var off = int.Parse(m.Groups["dec"].Value);
                        if (off >= 2 && off <= 0x200)
                            info.LocalOffsets.Add(off);
                    }
                }

                funcInfos[fstart] = info;
            }

            sb.AppendLine(";-------------------------------------------");
            sb.AppendLine("; OFFSET BYTES DISASSEMBLY");
            sb.AppendLine(";-------------------------------------------");

            byte? lastAh = null;
            byte? lastAl = null;
            ushort? lastAxImm = null;
            ushort? lastBxImm = null;
            ushort? lastCxImm = null;
            ushort? lastDxImm = null;
            ushort? lastSiImm = null;
            ushort? lastDiImm = null;
            ushort? lastDsImm = null;
            ushort? lastEsImm = null;
            FunctionInfo currentFunc = null;

            for (var i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;

                if (mzInsights && functionStarts.Contains(addr))
                {
                    sb.AppendLine();
                    sb.AppendLine($"func_{addr:X5}:");
                    if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                        sb.AppendLine($"; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X}"))}");

                    currentFunc = funcInfos.TryGetValue(addr, out var fi) ? fi : null;
                    lastAh = null;
                    lastAl = null;
                    lastAxImm = null;
                    lastBxImm = null;
                    lastCxImm = null;
                    lastDxImm = null;
                    lastSiImm = null;
                    lastDiImm = null;
                    lastDsImm = null;
                    lastEsImm = null;

                    if (mzInsights && currentFunc != null)
                    {
                        if (currentFunc.HasFrame)
                        {
                            if (currentFunc.ArgOffsets.Count > 0)
                            {
                                var args = currentFunc.ArgOffsets.Select(o => $"arg{(o - 4) / 2}@+0x{o:X}").ToList();
                                sb.AppendLine($"; ARGS: {string.Join(", ", args)}");
                            }
                            if (currentFunc.LocalOffsets.Count > 0)
                            {
                                var locals = currentFunc.LocalOffsets.Select(o => $"local_0x{o:X}").ToList();
                                sb.AppendLine($"; LOCALS: {string.Join(", ", locals)}");
                            }
                        }
                        if (currentFunc.RetPopBytes.HasValue && currentFunc.RetPopBytes.Value > 0)
                        {
                            var argc = currentFunc.RetPopBytes.Value / 2;
                            sb.AppendLine($"; PROTO?: callee pops {currentFunc.RetPopBytes.Value} bytes (~{argc} args)");
                        }

                        var summary = TrySummarizeFunction(currentFunc, instructions);
                        if (!string.IsNullOrEmpty(summary))
                            sb.AppendLine($"; SUMMARY: {summary}");
                    }
                }
                else if (mzInsights && labelTargets.Contains(addr))
                {
                    sb.AppendLine($"loc_{addr:X5}:");
                    if (jumpXrefs.TryGetValue(addr, out var sources) && sources.Count > 0)
                        sb.AppendLine($"; XREF: jumped from {string.Join(", ", sources.Distinct().OrderBy(x => x).Select(x => $"0x{x:X}"))}");
                }

                var bytes = BitConverter.ToString(ins.Bytes).Replace("-", string.Empty);
                var insText = ins.ToString();

                if (mzInsights)
                {
                    // Track a tiny amount of state for DOS interrupt hints.
                    UpdateSimpleDosState(ins, ref lastAh, ref lastAl, ref lastAxImm, ref lastBxImm, ref lastCxImm, ref lastDxImm, ref lastSiImm, ref lastDiImm, ref lastDsImm, ref lastEsImm);

                    var higherHint = TryGetHigherLevelHint(ins, i > 0 ? instructions[i - 1] : null, lastAh, lastAl, lastAxImm, lastBxImm, lastCxImm, lastDxImm, lastSiImm, lastDiImm, lastDsImm, lastEsImm);
                    if (!string.IsNullOrEmpty(higherHint))
                        insText += $" ; {higherHint}";
                }

                if (mzInsights && TryGetRelativeBranchTarget16(ins, out var target2, out var isCall2))
                {
                    if (target2 >= startOffset && target2 < startOffset + (uint)codeLen)
                    {
                        var label = isCall2 ? $"func_{target2:X5}" : $"loc_{target2:X5}";
                        insText += $" ; {(isCall2 ? "call" : "jmp")} {label}";
                    }
                }

                if (mzInsights && stringSyms != null && stringSyms.Count > 0)
                {
                    // Replace any 0x.... literal with known string symbol (within module).
                    insText = RewriteKnownStringLiteral(insText, stringSyms);
                    var inline = TryInlineStringPreview(insText, stringPrev);
                    if (!string.IsNullOrEmpty(inline))
                        insText += $" ; {inline}";
                }

                if (mzInsights && currentFunc != null && currentFunc.HasFrame)
                {
                    insText = RewriteBpFrameOperands(insText, currentFunc);
                }

                if (mzInsights)
                {
                    var hint = TryDecodeInterruptHint(ins, lastAh, lastAl, lastAxImm, lastBxImm, lastCxImm, lastDxImm, lastSiImm, lastDiImm, lastDsImm, lastEsImm, stringSyms, stringPrev, module);
                    if (!string.IsNullOrEmpty(hint))
                        insText += $" ; {hint}";
                }

                sb.AppendLine($"{addr:X5}h {bytes.PadRight(16, ' ')} {insText}");
            }

            output = sb.ToString();
            return true;
        }

        private readonly struct ToolchainMarker
        {
            public readonly int Offset;
            public readonly string Text;

            public ToolchainMarker(int offset, string text)
            {
                Offset = offset;
                Text = text;
            }
        }

        private static List<ToolchainMarker> FindToolchainMarkers(byte[] module, EnumToolchainHint hint, int maxTotalHits)
        {
            var markers = new List<ToolchainMarker>();
            if (module == null || module.Length == 0)
                return markers;

            // Keep this intentionally conservative; these strings are common and low-risk to detect.
            string[] needles;
            switch (hint)
            {
                case EnumToolchainHint.Borland:
                    needles = new[] { "Borland", "Turbo C", "Turbo Pascal", "TC++", "TURBO" };
                    break;
                case EnumToolchainHint.Watcom:
                    needles = new[] { "WATCOM", "Watcom" };
                    break;
                default:
                    needles = new string[0];
                    break;
            }

            foreach (var needle in needles)
            {
                if (markers.Count >= maxTotalHits)
                    break;

                foreach (var off in FindAsciiOccurrences(module, needle, maxHits: Math.Max(1, maxTotalHits - markers.Count)))
                {
                    markers.Add(new ToolchainMarker(off, $"\"{needle}\""));
                    if (markers.Count >= maxTotalHits)
                        break;
                }
            }

            return markers;
        }

        private static IEnumerable<int> FindAsciiOccurrences(byte[] data, string needle, int maxHits)
        {
            if (maxHits <= 0)
                yield break;
            if (data == null || data.Length == 0)
                yield break;
            if (string.IsNullOrEmpty(needle))
                yield break;

            var nb = Encoding.ASCII.GetBytes(needle);
            if (nb.Length == 0 || nb.Length > data.Length)
                yield break;

            var hits = 0;
            for (var i = 0; i <= data.Length - nb.Length; i++)
            {
                var ok = true;
                for (var j = 0; j < nb.Length; j++)
                {
                    if (data[i + j] != nb[j])
                    {
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                    continue;

                yield return i;
                hits++;
                if (hits >= maxHits)
                    yield break;

                // Avoid pathological overlaps.
                i += nb.Length - 1;
            }
        }

        private static bool TryParseMZHeader(byte[] fileBytes, out MZHeader h)
        {
            h = null;
            if (fileBytes == null || fileBytes.Length < 64)
                return false;
            if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
                return false;

            h = new MZHeader
            {
                e_magic = ReadUInt16(fileBytes, 0x00),
                e_cblp = ReadUInt16(fileBytes, 0x02),
                e_cp = ReadUInt16(fileBytes, 0x04),
                e_crlc = ReadUInt16(fileBytes, 0x06),
                e_cparhdr = ReadUInt16(fileBytes, 0x08),
                e_minalloc = ReadUInt16(fileBytes, 0x0A),
                e_maxalloc = ReadUInt16(fileBytes, 0x0C),
                e_ss = ReadUInt16(fileBytes, 0x0E),
                e_sp = ReadUInt16(fileBytes, 0x10),
                e_csum = ReadUInt16(fileBytes, 0x12),
                e_ip = ReadUInt16(fileBytes, 0x14),
                e_cs = ReadUInt16(fileBytes, 0x16),
                e_lfarlc = ReadUInt16(fileBytes, 0x18),
                e_ovno = ReadUInt16(fileBytes, 0x1A),
                e_lfanew = fileBytes.Length >= 0x40 ? ReadUInt32(fileBytes, 0x3C) : 0
            };

            return true;
        }

        private static int ComputeMzFileSizeBytes(MZHeader h, int fallbackLen)
        {
            if (h == null)
                return fallbackLen;
            if (h.e_cp == 0)
                return fallbackLen;

            var size = (h.e_cp - 1) * 512;
            if (h.e_cblp == 0)
                size += 512;
            else
                size += h.e_cblp;
            return (int)size;
        }

        private static ushort ReadUInt16(byte[] b, int off)
        {
            if (b == null || off < 0 || off + 2 > b.Length)
                return 0;
            return (ushort)(b[off] | (b[off + 1] << 8));
        }

        private static uint ReadUInt32(byte[] b, int off)
        {
            if (b == null || off < 0 || off + 4 > b.Length)
                return 0;
            return (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
        }

        private static bool TryGetRelativeBranchTarget16(Instruction ins, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return false;

            // Decode a subset of common relative branches/calls (16-bit mode):
            // - E8 iw  : CALL rel16
            // - E9 iw  : JMP rel16
            // - EB ib  : JMP rel8
            // - 70-7F ib : Jcc rel8
            // - 0F 80-8F iw : Jcc rel16
            var op0 = b[0];
            var baseOff = (uint)ins.Offset;

            if (op0 == 0xE8 && b.Length >= 3)
            {
                isCall = true;
                var rel = (short)(b[1] | (b[2] << 8));
                var t = (int)baseOff + b.Length + rel;
                if (t < 0)
                    return false;
                target = (uint)t;
                return true;
            }

            if (op0 == 0xE9 && b.Length >= 3)
            {
                var rel = (short)(b[1] | (b[2] << 8));
                var t = (int)baseOff + b.Length + rel;
                if (t < 0)
                    return false;
                target = (uint)t;
                return true;
            }

            if (op0 == 0xEB && b.Length >= 2)
            {
                var rel = (sbyte)b[1];
                var t = (int)baseOff + b.Length + rel;
                if (t < 0)
                    return false;
                target = (uint)t;
                return true;
            }

            if (op0 >= 0x70 && op0 <= 0x7F && b.Length >= 2)
            {
                var rel = (sbyte)b[1];
                var t = (int)baseOff + b.Length + rel;
                if (t < 0)
                    return false;
                target = (uint)t;
                return true;
            }

            if (op0 == 0x0F && b.Length >= 4)
            {
                var op1 = b[1];
                if (op1 >= 0x80 && op1 <= 0x8F)
                {
                    var rel = (short)(b[2] | (b[3] << 8));
                    var t = (int)baseOff + b.Length + rel;
                    if (t < 0)
                        return false;
                    target = (uint)t;
                    return true;
                }
            }

            return false;
        }

        private static void ScanStrings(byte[] module, out Dictionary<uint, string> syms, out Dictionary<uint, string> prev)
        {
            syms = new Dictionary<uint, string>();
            prev = new Dictionary<uint, string>();
            if (module == null || module.Length == 0)
                return;

            for (var i = 0; i < module.Length; i++)
            {
                if (module[i] < 0x20 || module[i] > 0x7E)
                    continue;

                var start = i;
                var sb = new StringBuilder();
                while (i < module.Length && module[i] >= 0x20 && module[i] <= 0x7E && sb.Length < 200)
                {
                    sb.Append((char)module[i]);
                    i++;
                }

                var term = i < module.Length ? module[i] : (byte)0;
                var nul = term == 0x00;
                var dollar = term == (byte)'$';
                var s = sb.ToString();

                // DOS often uses '$'-terminated strings (INT 21h/AH=09h), while C code uses NUL.
                if ((nul || dollar) && s.Length >= 4)
                {
                    var addr = (uint)start;
                    if (!syms.ContainsKey(addr))
                    {
                        syms[addr] = $"s_{addr:X5}";
                        prev[addr] = EscapeForComment(s);
                    }
                }

                if (nul || dollar)
                    i++;
            }
        }

        private static string EscapeForComment(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;
            s = s.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            if (s.Length > 120)
                s = s.Substring(0, 120) + "...";
            return s;
        }

        private static string RewriteKnownStringLiteral(string insText, Dictionary<uint, string> stringSyms)
        {
            if (string.IsNullOrEmpty(insText) || stringSyms == null || stringSyms.Count == 0)
                return insText;

            return Regex.Replace(insText, @"0x(?<hex>[0-9a-fA-F]{1,5})", m =>
            {
                var hex = m.Groups["hex"].Value;
                var val = Convert.ToUInt32(hex, 16);
                if (stringSyms.TryGetValue(val, out var sym))
                    return sym;
                return m.Value;
            });
        }

        private static string TryInlineStringPreview(string insText, Dictionary<uint, string> stringPrev)
        {
            if (string.IsNullOrEmpty(insText) || stringPrev == null || stringPrev.Count == 0)
                return string.Empty;

            var m = Regex.Match(insText, @"\bs_(?<hex>[0-9a-fA-F]{1,5})\b");
            if (!m.Success)
                return string.Empty;

            var addr = Convert.ToUInt32(m.Groups["hex"].Value, 16);
            if (stringPrev.TryGetValue(addr, out var prev))
                return $"STR: \"{prev}\"";

            return string.Empty;
        }

        private static string RewriteBpFrameOperands(string insText, FunctionInfo func)
        {
            if (string.IsNullOrEmpty(insText) || func == null || !func.HasFrame)
                return insText;

            // Rewrite [bp+0xNN] -> [argN]
            insText = Regex.Replace(insText, @"\[bp\+0x(?<hex>[0-9a-fA-F]+)\]", m =>
            {
                var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                if (off >= 4)
                {
                    var argN = (off - 4) / 2;
                    return $"[arg{argN}]";
                }
                return m.Value;
            });
            insText = Regex.Replace(insText, @"\[bp\+(?<dec>\d+)\]", m =>
            {
                var off = int.Parse(m.Groups["dec"].Value);
                if (off >= 4)
                {
                    var argN = (off - 4) / 2;
                    return $"[arg{argN}]";
                }
                return m.Value;
            });

            // Rewrite [bp-0xNN] -> [local_0xNN]
            insText = Regex.Replace(insText, @"\[bp\-0x(?<hex>[0-9a-fA-F]+)\]", m =>
            {
                var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                if (off > 0)
                    return $"[local_0x{off:X}]";
                return m.Value;
            });
            insText = Regex.Replace(insText, @"\[bp\-(?<dec>\d+)\]", m =>
            {
                var off = int.Parse(m.Groups["dec"].Value);
                if (off > 0)
                    return $"[local_0x{off:X}]";
                return m.Value;
            });

            return insText;
        }

        private static string TrySummarizeFunction(FunctionInfo func, List<Instruction> instructions)
        {
            if (func == null || instructions == null)
                return string.Empty;
            if (func.StartIndex < 0 || func.StartIndex >= instructions.Count)
                return string.Empty;

            var endIdx = Math.Min(func.EndIndex, instructions.Count);
            if (endIdx <= func.StartIndex)
                return string.Empty;

            // Recognize simple helper wrappers around common INT 21h services.
            // Keep this intentionally conservative: only emit summaries when we're highly confident.
            //
            // Pattern: DOS Get File Attributes wrapper
            //   AH=43h, AL=00h
            //   lds dx, [argX]   (far filename pointer)
            //   int 21h
            //   jb/jc fail
            //   les bx, [argY]   (far out-pointer)
            //   mov [es:bx], cx  (store attr)
            //   xor ax, ax       (return 0)
            //   (fail path returns 1)

            const int scanLimit = 80;
            var scanEnd = Math.Min(endIdx, func.StartIndex + scanLimit);

            int? int21Idx = null;
            for (var i = func.StartIndex; i < scanEnd; i++)
            {
                var b = instructions[i].Bytes;
                if (b != null && b.Length >= 2 && b[0] == 0xCD && b[1] == 0x21)
                {
                    int21Idx = i;
                    break;
                }
            }

            if (!int21Idx.HasValue)
                return string.Empty;

            var idx = int21Idx.Value;

            byte? ah = null;
            byte? al = null;
            int? filenameArgOff = null;

            for (var i = Math.Max(func.StartIndex, idx - 8); i < idx; i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length == 0)
                    continue;

                // mov ah, imm8
                if (b.Length >= 2 && b[0] == 0xB4)
                    ah = b[1];

                // mov al, imm8
                if (b.Length >= 2 && b[0] == 0xB0)
                    al = b[1];

                // xor al, al
                if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xC0)
                    al = 0;

                if (!filenameArgOff.HasValue && TryDecodeLdsDxFromBp(b, out var bpOff))
                    filenameArgOff = bpOff;
            }

            if (ah != 0x43 || al != 0x00)
                return string.Empty;
            if (!filenameArgOff.HasValue)
                return string.Empty;

            // Find the first carry-based conditional branch following int 21h.
            int? jccIdx = null;
            for (var i = idx + 1; i < Math.Min(scanEnd, idx + 8); i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length < 1)
                    continue;

                // 72 = JC/JB (carry set), 73 = JNC/JAE (carry clear)
                if (b[0] == 0x72 || b[0] == 0x73)
                {
                    jccIdx = i;
                    break;
                }
            }

            if (!jccIdx.HasValue)
                return string.Empty;

            int? outArgOff = null;
            var sawStoreCx = false;
            var sawXorAxAx = false;
            for (var i = jccIdx.Value + 1; i < Math.Min(scanEnd, jccIdx.Value + 20); i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length == 0)
                    continue;

                if (!outArgOff.HasValue && TryDecodeLesBxFromBp(b, out var bpOff))
                    outArgOff = bpOff;

                if (IsMovWordPtrEsBxFromCx(b))
                    sawStoreCx = true;

                if (b.Length >= 2 && b[0] == 0x33 && b[1] == 0xC0)
                    sawXorAxAx = true;
            }

            if (!outArgOff.HasValue || !sawStoreCx || !sawXorAxAx)
                return string.Empty;

            // Best-effort: look for a very nearby "return 1" on failure.
            var failureReturnsOne = false;
            for (var i = idx + 1; i < scanEnd; i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length == 0)
                    continue;

                // mov ax, 1 : B8 01 00
                if (b.Length >= 3 && b[0] == 0xB8 && b[1] == 0x01 && b[2] == 0x00)
                {
                    failureReturnsOne = true;
                    break;
                }
            }

            var inArgName = FormatArgNameFromBpOffset(filenameArgOff.Value);
            var outArgName = FormatArgNameFromBpOffset(outArgOff.Value);

            var retText = failureReturnsOne ? "returns 0 on success, 1 on failure" : "returns 0 on success, nonzero on failure";
            return $"Gets DOS file attributes for filename at {inArgName} (far ptr), stores CX to *{outArgName} (far ptr), {retText}.";
        }

        private static string FormatArgNameFromBpOffset(int bpOff)
        {
            if (bpOff < 4)
                return $"bp+0x{bpOff:X}";
            var argN = (bpOff - 4) / 2;
            return $"arg{argN}@+0x{bpOff:X}";
        }

        private static bool TryDecodeLdsDxFromBp(byte[] b, out int bpOff)
        {
            bpOff = 0;
            if (b == null || b.Length < 3)
                return false;
            if (b[0] != 0xC5)
                return false;

            var modrm = b[1];
            var mod = (modrm >> 6) & 0x3;
            var reg = (modrm >> 3) & 0x7;
            var rm = modrm & 0x7;

            // reg=010 is DX
            if (reg != 0x2)
                return false;

            // We only accept [bp+disp] addressing forms.
            if (rm != 0x6)
                return false;

            if (mod == 0x1 && b.Length >= 3)
            {
                bpOff = unchecked((sbyte)b[2]);
                if (bpOff < 0)
                    return false;
                return true;
            }
            if (mod == 0x2 && b.Length >= 4)
            {
                bpOff = b[2] | (b[3] << 8);
                return true;
            }

            return false;
        }

        private static bool TryDecodeLesBxFromBp(byte[] b, out int bpOff)
        {
            bpOff = 0;
            if (b == null || b.Length < 3)
                return false;
            if (b[0] != 0xC4)
                return false;

            var modrm = b[1];
            var mod = (modrm >> 6) & 0x3;
            var reg = (modrm >> 3) & 0x7;
            var rm = modrm & 0x7;

            // reg=011 is BX
            if (reg != 0x3)
                return false;
            if (rm != 0x6)
                return false;

            if (mod == 0x1 && b.Length >= 3)
            {
                bpOff = unchecked((sbyte)b[2]);
                if (bpOff < 0)
                    return false;
                return true;
            }
            if (mod == 0x2 && b.Length >= 4)
            {
                bpOff = b[2] | (b[3] << 8);
                return true;
            }

            return false;
        }

        private static bool IsMovWordPtrEsBxFromCx(byte[] b)
        {
            if (b == null || b.Length == 0)
                return false;

            // Accept:
            //   26 89 0F   mov [es:bx], cx
            //   89 0F      mov [bx], cx  (rare, but allow)
            if (b.Length >= 3 && b[0] == 0x26 && b[1] == 0x89 && b[2] == 0x0F)
                return true;
            if (b.Length >= 2 && b[0] == 0x89 && b[1] == 0x0F)
                return true;

            return false;
        }

        private static void UpdateSimpleDosState(
            Instruction ins,
            ref byte? lastAh,
            ref byte? lastAl,
            ref ushort? lastAxImm,
            ref ushort? lastBxImm,
            ref ushort? lastCxImm,
            ref ushort? lastDxImm,
            ref ushort? lastSiImm,
            ref ushort? lastDiImm,
            ref ushort? lastDsImm,
            ref ushort? lastEsImm)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return;

            string text = ins.ToString().ToLower();

            // xor reg, reg or sub reg, reg
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ixor || ins.Mnemonic == ud_mnemonic_code.UD_Isub)
            {
                if (text.Contains("ax, ax")) { lastAxImm = 0; lastAh = 0; lastAl = 0; return; }
                if (text.Contains("bx, bx")) { lastBxImm = 0; return; }
                if (text.Contains("cx, cx")) { lastCxImm = 0; return; }
                if (text.Contains("dx, dx")) { lastDxImm = 0; return; }
                if (text.Contains("si, si")) { lastSiImm = 0; return; }
                if (text.Contains("di, di")) { lastDiImm = 0; return; }
            }

            // xor al, al: 30 C0
            if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xC0)
            {
                lastAl = 0;
                if (lastAh.HasValue)
                    lastAxImm = (ushort)(lastAh.Value << 8);
                else if (lastAxImm.HasValue)
                    lastAxImm = (ushort)(lastAxImm.Value & 0xFF00);
                return;
            }

            // mov ah, imm8: B4 ib
            if (b[0] == 0xB4 && b.Length >= 2)
            {
                lastAh = b[1];
                if (lastAl.HasValue) lastAxImm = (ushort)((lastAh.Value << 8) | lastAl.Value);
                else lastAxImm = null;
                return;
            }

            // mov al, imm8: B0 ib
            if (b[0] == 0xB0 && b.Length >= 2)
            {
                lastAl = b[1];
                if (lastAh.HasValue) lastAxImm = (ushort)((lastAh.Value << 8) | lastAl.Value);
                else if (lastAxImm.HasValue) lastAxImm = (ushort)((lastAxImm.Value & 0xFF00) | lastAl.Value);
                return;
            }

            // mov ax, imm16: B8 iw
            if (b[0] == 0xB8 && b.Length >= 3)
            {
                lastAxImm = (ushort)(b[1] | (b[2] << 8));
                lastAh = (byte)(lastAxImm >> 8);
                lastAl = (byte)(lastAxImm & 0xFF);
                return;
            }

            // mov bx, imm16: BB iw
            if (b[0] == 0xBB && b.Length >= 3)
            {
                lastBxImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // mov cx, imm16: B9 iw
            if (b[0] == 0xB9 && b.Length >= 3)
            {
                lastCxImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // mov dx, imm16: BA iw
            if (b[0] == 0xBA && b.Length >= 3)
            {
                lastDxImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // mov si, imm16: BE iw
            if (b[0] == 0xBE && b.Length >= 3)
            {
                lastSiImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // mov di, imm16: BF iw
            if (b[0] == 0xBF && b.Length >= 3)
            {
                lastDiImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // Register-to-register moves (subset of common ones)
            if (b.Length >= 2 && b[0] == 0x89) // mov r/m, r
            {
                if (b[1] == 0xC3) { lastBxImm = lastAxImm; return; } // mov bx, ax
                if (b[1] == 0xC1) { lastCxImm = lastAxImm; return; } // mov cx, ax
                if (b[1] == 0xC2) { lastDxImm = lastAxImm; return; } // mov dx, ax
            }
            if (b.Length >= 2 && b[0] == 0x8B) // mov r, r/m
            {
                if (b[1] == 0xD8) { lastBxImm = lastAxImm; return; } // mov bx, ax
                if (b[1] == 0xC8) { lastCxImm = lastAxImm; return; } // mov cx, ax
                if (b[1] == 0xD0) { lastDxImm = lastAxImm; return; } // mov dx, ax
                if (b[1] == 0xC3) { lastAxImm = lastBxImm; lastAh = lastAxImm.HasValue ? (byte?)(lastAxImm >> 8) : null; lastAl = lastAxImm.HasValue ? (byte?)(lastAxImm & 0xFF) : null; return; } // mov ax, bx
            }

            // Segments
            if (b[0] == 0x8E && b.Length >= 2)
            {
                if (b[1] == 0xD8) { lastDsImm = lastAxImm; return; } // mov ds, ax
                if (b[1] == 0xDA) { lastDsImm = lastDxImm; return; } // mov ds, dx
                if (b[1] == 0xC0) { lastEsImm = lastAxImm; return; } // mov es, ax
                if (b[1] == 0xC2) { lastEsImm = lastDxImm; return; } // mov es, dx
                if (b[1] == 0xD1) { lastDsImm = null; return; }     // mov ds, ss (clobber)
                if (b[1] == 0xC8) { lastEsImm = lastCxImm; return; } // mov es, cx
            }

            // Basic Arithmetic (Constant Propagation)
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iinc)
            {
                if (text.Contains("ax") && lastAxImm.HasValue) { lastAxImm++; lastAh = (byte?)(lastAxImm >> 8); lastAl = (byte?)(lastAxImm & 0xFF); return; }
                if (text.Contains("bx") && lastBxImm.HasValue) { lastBxImm++; return; }
                if (text.Contains("cx") && lastCxImm.HasValue) { lastCxImm++; return; }
                if (text.Contains("dx") && lastDxImm.HasValue) { lastDxImm++; return; }
            }
            if (ins.Mnemonic == ud_mnemonic_code.UD_Idec)
            {
                if (text.Contains("ax") && lastAxImm.HasValue) { lastAxImm--; lastAh = (byte?)(lastAxImm >> 8); lastAl = (byte?)(lastAxImm & 0xFF); return; }
                if (text.Contains("bx") && lastBxImm.HasValue) { lastBxImm--; return; }
                if (text.Contains("cx") && lastCxImm.HasValue) { lastCxImm--; return; }
                if (text.Contains("dx") && lastDxImm.HasValue) { lastDxImm--; return; }
            }

            // Clobber logic for instructions that modify registers in ways we don't track as constants
            var firstComma = text.IndexOf(',');
            var dest = firstComma != -1 ? text.Substring(0, firstComma) : text;

            if (dest.Contains("ax") || dest.Contains("ah") || dest.Contains("al")) { lastAxImm = null; lastAh = null; lastAl = null; }
            else if (dest.Contains("bx")) lastBxImm = null;
            else if (dest.Contains("cx")) lastCxImm = null;
            else if (dest.Contains("dx")) lastDxImm = null;
            else if (dest.Contains("si")) lastSiImm = null;
            else if (dest.Contains("di")) lastDiImm = null;
            else if (dest.Contains("ds")) lastDsImm = null;
            else if (dest.Contains("es")) lastEsImm = null;

            // Special case: pop, call, mul, div, etc. clobber implicit registers
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop || ins.Mnemonic == ud_mnemonic_code.UD_Icall || 
                ins.Mnemonic == ud_mnemonic_code.UD_Imul || ins.Mnemonic == ud_mnemonic_code.UD_Idiv ||
                ins.Mnemonic == ud_mnemonic_code.UD_Iloop || ins.Mnemonic == ud_mnemonic_code.UD_Iloope || ins.Mnemonic == ud_mnemonic_code.UD_Iloopne ||
                ins.Mnemonic == ud_mnemonic_code.UD_Imovsb || ins.Mnemonic == ud_mnemonic_code.UD_Imovsw || ins.Mnemonic == ud_mnemonic_code.UD_Istosb || ins.Mnemonic == ud_mnemonic_code.UD_Istosw)
            {
                if (ins.Mnemonic == ud_mnemonic_code.UD_Icall || ins.Mnemonic == ud_mnemonic_code.UD_Imul || ins.Mnemonic == ud_mnemonic_code.UD_Idiv)
                {
                    lastAxImm = null; lastAh = null; lastAl = null;
                    lastDxImm = null; 
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Iloop || ins.Mnemonic == ud_mnemonic_code.UD_Iloope || ins.Mnemonic == ud_mnemonic_code.UD_Iloopne)
                {
                    lastCxImm = null;
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Imovsb || ins.Mnemonic == ud_mnemonic_code.UD_Imovsw || ins.Mnemonic == ud_mnemonic_code.UD_Istosb || ins.Mnemonic == ud_mnemonic_code.UD_Istosw)
                {
                    lastSiImm = null; lastDiImm = null;
                    if (text.Contains("rep")) lastCxImm = 0;
                }
            }
        }

        private static string TryGetHigherLevelHint(
            Instruction ins,
            Instruction prev,
            byte? ah, byte? al,
            ushort? ax, ushort? bx, ushort? cx, ushort? dx,
            ushort? si, ushort? di,
            ushort? ds, ushort? es)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0) return null;
            var text = ins.ToString();

            // Stack switch: mov sp, reg after mov ss, reg
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && text.Contains("sp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Imov && prev.ToString().Contains("ss"))
            {
                if (Regex.IsMatch(text, @"\bsp\b") && Regex.IsMatch(prev.ToString(), @"\bss\b"))
                {
                    return "SETUP STACK";
                }
            }

            // Segment setup
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && ax.HasValue && text.Contains("ax"))
            {
                if (Regex.IsMatch(text, @"\bds\b,\s*ax\b")) return $"SET DS=0x{ax.Value:X4}";
                if (Regex.IsMatch(text, @"\bes\b,\s*ax\b")) return $"SET ES=0x{ax.Value:X4}";
                if (Regex.IsMatch(text, @"\bss\b,\s*ax\b")) return $"SET SS=0x{ax.Value:X4}";
            }

            // Direction flag
            if (ins.Mnemonic == ud_mnemonic_code.UD_Icld) return "Direction: Forward";
            if (ins.Mnemonic == ud_mnemonic_code.UD_Istd) return "Direction: Backward";

            // ES = DS
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop && text.Contains("es") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Ipush && prev.ToString().Contains("ds"))
            {
                if (Regex.IsMatch(text, @"\bes\b") && Regex.IsMatch(prev.ToString(), @"\bds\b"))
                    return "ES = DS";
            }

            // REP STOSB: memset
            if (b[0] == 0xF3 && b.Length >= 2 && b[1] == 0xAA)
            {
                string detail = "memset";
                if (es.HasValue && di.HasValue) detail += $"(ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $"(DI=0x{di.Value:X4}";
                else detail += "(";

                if (al.HasValue) detail += $", val=0x{al.Value:X2}";
                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";
                
                return detail;
            }

            // REP STOSW: memset (word)
            if (b[0] == 0xF3 && b.Length >= 2 && b[1] == 0xAB)
            {
                string detail = "memsetw";
                if (es.HasValue && di.HasValue) detail += $"(ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $"(DI=0x{di.Value:X4}";
                else detail += "(";

                if (ax.HasValue) detail += $", val=0x{ax.Value:X4}";
                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";

                return detail;
            }

            // REP MOVSB/W: memcpy
            if (b[0] == 0xF3 && b.Length >= 2 && (b[1] == 0xA4 || b[1] == 0xA5))
            {
                bool isWord = b[1] == 0xA5;
                string detail = isWord ? "memmovew" : "memmoveb";
                if (ds.HasValue && si.HasValue) detail += $"(from DS:0x{si.Value:X4} [seg=0x{ds.Value:X4}]";
                else if (si.HasValue) detail += $"(from SI=0x{si.Value:X4}";
                else detail += "(from ?";

                if (es.HasValue && di.HasValue) detail += $", to ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $", to DI=0x{di.Value:X4}";
                else detail += ", to ?";

                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";

                return detail;
            }

            // REPNE SCASB: strlen
            if (b[0] == 0xF2 && b.Length >= 2 && b[1] == 0xAE)
            {
                return "strlen (find AL in ES:DI)";
            }

            // REPE CMPSB/W: memcmp
            if (b[0] == 0xF3 && b.Length >= 2 && (b[1] == 0xA6 || b[1] == 0xA7))
            {
                return $"memcmp { (b[1] == 0xA7 ? "word" : "byte") } (DS:SI vs ES:DI)";
            }

            // Far CALL to segment:offset
            if (b[0] == 0x9A && b.Length >= 5)
            {
                ushort off = (ushort)(b[1] | (b[2] << 8));
                ushort seg = (ushort)(b[3] | (b[4] << 8));
                return $"CALL FAR {seg:X4}:{off:X4}";
            }

            // Far JMP to segment:offset
            if (b[0] == 0xEA && b.Length >= 5)
            {
                ushort off = (ushort)(b[1] | (b[2] << 8));
                ushort seg = (ushort)(b[3] | (b[4] << 8));
                return $"JMP FAR {seg:X4}:{off:X4}";
            }

            // Function markers
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && text.Contains("bp, sp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Ipush && prev.ToString().Contains("bp"))
            {
                return "FUNC PROLOGUE";
            }
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop && text.Contains("bp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Imov && prev.ToString().Contains("sp, bp"))
            {
                return "FUNC EPILOGUE (LEAVE)";
            }

            // Segment pointer loads
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ilds) return "LDS: load DS:reg with far pointer";
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iles) return "LES: load ES:reg with far pointer";

            // INT 3: Debug break
            if (b[0] == 0xCC) return "DEBUG BREAK";

            return null;
        }

        private static string TryDecodeInterruptHint(
            Instruction ins,
            byte? lastAh,
            byte? lastAl,
            ushort? lastAxImm,
            ushort? lastBxImm,
            ushort? lastCxImm,
            ushort? lastDxImm,
            ushort? lastSiImm,
            ushort? lastDiImm,
            ushort? lastDsImm,
            ushort? lastEsImm,
            Dictionary<uint, string> stringSyms,
            Dictionary<uint, string> stringPrev,
            byte[] module)
        {
            var b = ins.Bytes;
            if (b == null || b.Length < 2)
                return string.Empty;

            // int imm8: CD ib
            if (b[0] != 0xCD)
                return string.Empty;

            var intNo = b[1];

            if (intNo == 0x00) return "CPU: Divide By Zero";
            if (intNo == 0x01) return "CPU: Single Step / Trace";
            if (intNo == 0x02) return "CPU: Non-Maskable Interrupt (NMI)";
            if (intNo == 0x03) return "CPU: Breakpoint (INT 3)";
            if (intNo == 0x04) return "CPU: Overflow (INTO)";
            if (intNo == 0x05) return "CPU: Bounds Check / Print Screen";
            if (intNo == 0x06) return "CPU: Invalid Opcode";
            if (intNo == 0x07) return "CPU: Coprocessor Not Available";
            if (intNo == 0x08) return "IRQ0: System Timer Tick";
            if (intNo == 0x09) return "IRQ1: Keyboard String / IRQ9: Redirected IRQ2";

            if (intNo == 0x10) return "BIOS: VIDEO SERVICES (AH=mode/pos/char/scroll/VBE)";
            if (intNo == 0x11) return "BIOS: Get Equipment List ; AX bits: 0=diskette, 1=8087, 4-5=video, 6-7=drives";
            if (intNo == 0x12) return "BIOS: Get Memory Size ; AX=KB (max 640)";
            if (intNo == 0x13) return "BIOS: DISK I/O (CH/CL=cyl/sec, DH/DL=head/drive, ES:BX=buffer)";
            if (intNo == 0x14) return "BIOS: SERIAL I/O (DX=port)";
            if (intNo == 0x15) return "BIOS: SYSTEM SERVICES (Wait/Copy/A20/E820/Joystick)";
            if (intNo == 0x16) return "BIOS: KEYBOARD I/O";
            if (intNo == 0x17) return "BIOS: PRINTER I/O";

            if (intNo == 0x2F) return "MULTIPLEX INTERRUPT (Print/Eject/DPMI/XMS/Cache)";
            if (intNo == 0x31) return "DPMI: DOS Protected Mode Interface";
            if (intNo == 0x33) return "MOUSE DRIVER API";
            if (intNo >= 0x34 && intNo <= 0x3E) return $"Borland Floating Point Emulator (INT {intNo:X2}h)";
            if (intNo >= 0x60 && intNo <= 0x66) return $"Perhaps Game Hook? (User Interrupt INT {intNo:X2}h)";
            if (intNo == 0x67) return "EMS: Expanded Memory (or Perhaps Game Hook?)";
            if (intNo == 0x18) return "BIOS: ROM BASIC";
            if (intNo == 0x19) return "BIOS: Reboot";
            if (intNo == 0x1A) return "BIOS: TIMER & PCI SERVICES (Get Ticks/Set Time/PCI Check)";
            if (intNo == 0x1B) return "BIOS: Ctrl-Break handler";
            if (intNo == 0x1C) return "BIOS: User Timer Tick";

            if (intNo == 0x20) return "DOS: terminate (CP/M style)";
            if (intNo == 0x25) return "DOS: absolute disk read";
            if (intNo == 0x26) return "DOS: absolute disk write";
            if (intNo == 0x27) return "DOS: terminate and stay resident (TSR)";
            if (intNo == 0x24) return "DOS: critical error handler service (internal)";
            if (intNo == 0x29) return "DOS: fast console output (internal)";

            // Prefer database-driven descriptions.
            string dbDesc;
            if (DosInterruptDatabase.Instance.TryDescribe(intNo, lastAh, lastAxImm, out dbDesc) && !string.IsNullOrEmpty(dbDesc))
            {
                // Best-effort inline detail for common DS:DX or DS:SI filename/string/buffer APIs.
                if (intNo == 0x21 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;

                    // AH=01, 02, 05, 06, 07, 08: Basic I/O
                    if (ah == 0x01) dbDesc += " ; (returns AL=char)";
                    if (ah == 0x02) { if (lastDxImm.HasValue) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL=char"; }
                    if (ah == 0x05) { if (lastDxImm.HasValue) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL=char"; }
                    if (ah == 0x06) { if (lastDxImm.HasValue && (lastDxImm.Value & 0xFF) != 0xFF) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL: FF=input, else=output char"; }

                    // Extra detail: DOS file attribute bit meanings (AH=43h).
                    // AL=00h Get Attributes returns CX, AL=01h Set Attributes takes CX.
                    if (ah == 0x43)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);

                        if (al == 0x00)
                            dbDesc += " ; returns CX bits: 0x01=RO 0x02=Hidden 0x04=System 0x08=VolLabel 0x10=Dir 0x20=Archive";
                        else if (al == 0x01)
                            dbDesc += " ; CX bits: 0x01=RO 0x02=Hidden 0x04=System 0x08=VolLabel 0x10=Dir 0x20=Archive";
                    }

                    // AH=0Eh: Select Default Drive
                    if (ah == 0x0E)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF} ({ (char)('A' + (lastDxImm.Value & 0xFF)) }:)";
                        dbDesc += " ; DL=drive(0=A 1=B)";
                    }

                    // AH=19h: Get Default Drive
                    if (ah == 0x19)
                    {
                        dbDesc += " ; (returns AL=drive 0=A 1=B)";
                    }

                    // AH=33h: Get/Set Ctrl-Break
                    if (ah == 0x33)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "Get", 1 => "Set", 5 => "GetBootDrive", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        dbDesc += " ; AL: 0=Get 1=Set 5=BootDrive ; DL=state(0=off 1=on)";
                    }

                    // AH=36h: Get Free Space
                    if (ah == 0x36)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF} (0=def 1=A)";
                        dbDesc += " ; DL=drive";
                    }

                    // AH=3Dh: Open file
                    if (ah == 0x3D)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);

                        if (al.HasValue)
                        {
                            var acc = (al.Value & 0x03) switch { 0 => "R", 1 => "W", 2 => "RW", _ => "?" };
                            dbDesc += $" ; AL=0x{al.Value:X2} ({acc})";
                        }
                        
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var fn = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(fn)) dbDesc += $" ; path=\"{fn}\"";
                        }
                        dbDesc += " ; AL mode: 0=R 1=W 2=RW, bits 4-6: 0=Comp 1=DAll 2=DW 3=DR 4=DNone";
                    }

                    // AH=3Ch: Create file
                    if (ah == 0x3C)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var fn = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(fn)) dbDesc += $" ; path=\"{fn}\"";
                        }
                        if (lastCxImm.HasValue)
                        {
                            var attr = lastCxImm.Value;
                            var parts = new List<string>();
                            if ((attr & 0x01) != 0) parts.Add("RO");
                            if ((attr & 0x02) != 0) parts.Add("Hid");
                            if ((attr & 0x04) != 0) parts.Add("Sys");
                            if ((attr & 0x20) != 0) parts.Add("Arch");
                            if (parts.Count > 0) dbDesc += $" ; attr=0x{attr:X} ({string.Join("|", parts)})";
                        }
                    }

                    // AH=3Fh/40h: Read/Write
                    if (ah == 0x3F || ah == 0x40)
                    {
                        if (lastBxImm.HasValue)
                        {
                            var h = lastBxImm.Value;
                            var hname = h switch { 0 => "stdin", 1 => "stdout", 2 => "stderr", 3 => "stdaux", 4 => "stdprn", _ => $"handle 0x{h:X}" };
                            dbDesc += $" ; { (ah == 0x3F ? "read from" : "write to") } {hname}";
                        }
                        if (lastCxImm.HasValue) dbDesc += $" ; count={lastCxImm.Value}";
                    }

                    // AH=09h: Print $
                    if (ah == 0x09)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var s = TryReadDollarString(module, linear, 256);
                            if (!string.IsNullOrEmpty(s)) dbDesc += $" ; \"{s}\"";
                        }
                    }

                    // AH=25h: Set Interrupt Vector
                    if (ah == 0x25)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; SET INT {lastAl.Value:X2}h HOOK";
                        else if (lastAxImm.HasValue) dbDesc += $" ; SET INT {(byte)(lastAxImm.Value & 0xFF):X2}h HOOK";
                        dbDesc += " ; DS:DX -> new handler";
                    }
                    
                    // AH=35h: Get Interrupt Vector
                    if (ah == 0x35)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; GET INT {lastAl.Value:X2}h VECTOR";
                        dbDesc += " ; (returns ES:BX -> current handler)";
                    }

                    // AH=42h: LSeek
                    if (ah == 0x42)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);

                        if (al.HasValue)
                        {
                            var orig = al.Value switch { 0 => "Start", 1 => "Cur", 2 => "End", _ => "?" };
                            dbDesc += $" ; AL={al.Value} ({orig})";
                        }
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value}";
                        if (lastCxImm.HasValue && lastDxImm.HasValue)
                        {
                            long off = ((long)lastCxImm.Value << 16) | lastDxImm.Value;
                            dbDesc += $" ; offset={off} (0x{off:X})";
                        }
                        dbDesc += " ; AL origin: 0=Start 1=Cur 2=End ; BX=handle CX:DX=offset";
                    }

                    // AH=47h: Get Cur Dir
                    if (ah == 0x47)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF}";
                        dbDesc += " ; DL=drive(0=def 1=A 2=B) DS:SI=64b buffer";
                    }

                    // AH=48h: Allocate Memory
                    if (ah == 0x48)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value} paragraphs ({lastBxImm.Value * 16} bytes)";
                        dbDesc += " ; BX=paras (returns AX=seg)";
                    }

                    // AH=4Bh: EXEC
                    if (ah == 0x4B)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "LoadExec", 1 => "LoadDebug", 3 => "LoadOverlay", 5 => "SetExecState", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        dbDesc += " ; AL: 0=Exec 1=Debug 3=Overlay DS:DX=path ES:BX=params";
                    }

                    // AH=4Ah: Resize Memory Block
                    if (ah == 0x4A)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value} paragraphs ({lastBxImm.Value * 16} bytes)";
                        dbDesc += " ; ES=seg BX=paras";
                    }

                    // AH=1Ah: Set DTA
                    if (ah == 0x1A)
                    {
                        dbDesc += " ; DS:DX=DTA buffer";
                    }

                    // AH=2Ah/2Bh/2Ch/2Dh: Date/Time
                    if (ah == 0x2A || ah == 0x2B || ah == 0x2C || ah == 0x2D)
                    {
                        var mode = ah switch { 0x2A => "GetDate", 0x2B => "SetDate", 0x2C => "GetTime", 0x2D => "SetTime", _ => "" };
                        dbDesc += $" ; {mode}";
                    }

                    // AH=30h: Get DOS version
                    if (ah == 0x30)
                    {
                        dbDesc += " ; (returns AL=major AH=minor)";
                    }

                    // AH=4Ch: Terminate with code
                    if (ah == 0x4C)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; exit code {lastAl.Value}";
                        dbDesc += " ; AL=exit code";
                    }

                    // AH=39h, 0x3Ah, 0x3Bh: Mkdir/Rmdir/Chdir
                    if (ah == 0x39 || ah == 0x3A || ah == 0x3B)
                    {
                        dbDesc += " ; DS:DX=path";
                    }

                    // AH=4Eh: Find First
                    if (ah == 0x4E)
                    {
                        if (lastCxImm.HasValue)
                        {
                            var attr = lastCxImm.Value;
                            var parts = new List<string>();
                            if ((attr & 0x01) != 0) parts.Add("RO");
                            if ((attr & 0x02) != 0) parts.Add("Hid");
                            if ((attr & 0x04) != 0) parts.Add("Sys");
                            if ((attr & 0x08) != 0) parts.Add("Vol");
                            if ((attr & 0x10) != 0) parts.Add("Dir");
                            if ((attr & 0x20) != 0) parts.Add("Arch");
                            var attrStr = parts.Count > 0 ? string.Join("|", parts) : "Norm";
                            dbDesc += $" ; CX=0x{attr:X} ({attrStr})";
                        }
                        dbDesc += " ; CX attr: 1=RO 2=Hid 4=Sys 0x10=Dir 0x20=Arch ; DS:DX=path";
                    }

                    // AH=4Fh: Find Next
                    if (ah == 0x4F)
                    {
                        dbDesc += " ; (uses current DTA)";
                    }

                    // AH=56h: Rename
                    if (ah == 0x56)
                    {
                        dbDesc += " ; DS:DX=oldpath ES:DI=newpath";
                    }

                    // AH=57h: Get/Set File Time
                    if (ah == 0x57)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue) dbDesc += $" ; {(al.Value == 0 ? "Get" : "Set")}";
                        dbDesc += " ; AL: 0=Get 1=Set ; BX=handle CX=time DX=date";
                    }

                    // AH=58h: Get/Set Alloc Strategy
                    if (ah == 0x58)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "GetStrat", 1 => "SetStrat", 2 => "GetUMB", 3 => "SetUMB", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        dbDesc += " ; AL: 0=Get 1=Set 2=GetUMB 3=SetUMB";
                    }

                    // AH=62h: Get PSP
                    if (ah == 0x62)
                    {
                        dbDesc += " ; (returns BX=PSP segment)";
                    }

                    // AH=34h: Get In-DOS Flag
                    if (ah == 0x34)
                    {
                        dbDesc += " ; (returns ES:BX -> In-DOS flag)";
                    }

                    // AH=52h: Get List of Lists
                    if (ah == 0x52)
                    {
                        dbDesc += " ; (returns ES:BX -> LoL)";
                    }

                    // AH=6Ch: Extended Open/Create
                    if (ah == 0x6C)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX=0x{lastBxImm.Value:X} (mode)";
                        if (lastCxImm.HasValue) dbDesc += $" ; CX=0x{lastCxImm.Value:X} (attr)";
                        if (lastDxImm.HasValue) dbDesc += $" ; DX=0x{lastDxImm.Value:X} (action)";
                        dbDesc += " ; BX=mode CX=attr DX=action DS:SI=path";
                    }

                    // AH=44h: IOCTL
                    if (ah == 0x44)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);
                        
                        if (al.HasValue)
                        {
                            var sub = al.Value switch
                            {
                                0x00 => "GetDeviceInfo",
                                0x01 => "SetDeviceInfo",
                                0x02 => "Receive(Char)",
                                0x03 => "Send(Char)",
                                0x04 => "Receive(Control)",
                                0x05 => "Send(Control)",
                                0x06 => "GetInputStat",
                                0x07 => "GetOutputStat",
                                0x08 => "IsRemovable",
                                0x09 => "IsRemoteDrive",
                                0x0A => "IsRemoteHandle",
                                0x0B => "SetSharingRetry",
                                0x0D => "GenericBlockDevice",
                                0x0E => "GetDriveLogical",
                                0x0F => "SetDriveLogical",
                                _ => $"sub=0x{al.Value:X2}"
                            };
                            dbDesc += $" ; {sub}";
                        }
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value}";
                        dbDesc += " ; AL: 0=Get 1=Set 2=Rd 3=Wr 4=RdCtl 5=WrCtl 6=InStat 7=OutStat 8=Remov";
                    }

                    // AH=5Ch: Lock/Unlock
                    if (ah == 0x5C)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue) dbDesc += $" ; {(al.Value == 0 ? "Lock" : "Unlock")}";
                        dbDesc += " ; AL: 0=Lock 1=Unlock ; BX=handle CX:DX=offset SI:DI=length";
                    }

                    // AH=5Dh: File Sharing
                    if (ah == 0x5D)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0x00 => "ServerDosError", 0x06 => "GetAddressOfPSP", 0x0A => "SetExtendedError", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                    }

                    // AH=5Eh/5Fh: Network
                    if (ah == 0x5E || ah == 0x5F)
                    {
                        dbDesc += " ; Network/Redirection Service";
                    }

                    // FCB-based: 0x0F, 0x10, 0x11, 0x12, 0x13, 0x16, 0x17, 0x21, 0x22, 0x23, 0x24, 0x27, 0x28
                    if (ah == 0x0F || ah == 0x10 || ah == 0x11 || ah == 0x12 || ah == 0x13 || ah == 0x16 || ah == 0x17 || 
                        ah == 0x21 || ah == 0x22 || ah == 0x23 || ah == 0x24 || ah == 0x27 || ah == 0x28)
                    {
                        var fcDetail = TryFormatFcbDetail(lastDxImm, module);
                        if (!string.IsNullOrEmpty(fcDetail))
                            return dbDesc + " ; " + fcDetail;
                    }

                    // DX-based: $ print, path functions, handle I/O, etc.
                    if (ah == 0x09 || ah == 0x0A || ah == 0x1A || ah == 0x39 || ah == 0x3A || ah == 0x3B || ah == 0x3C || 
                        ah == 0x3D || ah == 0x3F || ah == 0x40 || ah == 0x41 || ah == 0x43 || ah == 0x4B || 
                        ah == 0x4E || ah == 0x56 || ah == 0x5A || ah == 0x5B)
                    {
                        var dxDetail = TryFormatPointerDetail(lastDxImm, lastDsImm, "DX", stringSyms, stringPrev);
                        if (!string.IsNullOrEmpty(dxDetail))
                            return dbDesc + " ; " + dxDetail;
                    }
                    // SI-based: 0x47 (Get Cur Dir), 0x6C (Ext Open), 0x71xx (LFN)
                    if (ah == 0x47 || ah == 0x6C || ah == 0x71)
                    {
                        var siDetail = TryFormatPointerDetail(lastSiImm, lastDsImm, "SI", stringSyms, stringPrev);
                        if (!string.IsNullOrEmpty(siDetail))
                            return dbDesc + " ; " + siDetail;
                    }
                }

                // BIOS Video
                if (intNo == 0x10 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x00) // Set Mode
                    {
                        var al = lastAl ?? (byte)(lastAxImm ?? 0);
                        var mode = al switch
                        {
                            0x03 => "80x25 Text",
                            0x04 => "320x200 4-color",
                            0x06 => "640x200 BW",
                            0x0D => "320x200 16-color (EGA)",
                            0x0E => "640x200 16-color (EGA)",
                            0x10 => "640x350 16-color (EGA)",
                            0x12 => "640x480 16-color (VGA)",
                            0x13 => "320x200 256-color (VGA)",
                            _ => $"mode 0x{al:X2}"
                        };
                        dbDesc += $" ; {mode}";
                    }
                    else if (ah == 0x01) // Set Cursor Shape
                    {
                        if (lastCxImm.HasValue) dbDesc += $" ; shape=0x{lastCxImm.Value:X4} (CH=start CL=end)";
                        dbDesc += " ; CH=start CL=end";
                    }
                    else if (ah == 0x02) // Set Cursor
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; row={lastDxImm.Value >> 8} col={lastDxImm.Value & 0xFF}";
                        dbDesc += " ; BH=page DH=row DL=col";
                    }
                    else if (ah == 0x03) // Get Cursor
                    {
                        dbDesc += " ; BH=page (returns CX=shape DX=pos)";
                    }
                    else if (ah == 0x06 || ah == 0x07) // Scroll Up/Down
                    {
                        if (lastAl.HasValue) dbDesc += $" ; lines={lastAl.Value}";
                        dbDesc += " ; AL=lines BH=attr CH,CL=top left DH,DL=bottom right";
                    }
                    else if (ah == 0x08) // Read Char/Attr
                    {
                        dbDesc += " ; BH=page (returns AL=char AH=attr)";
                    }
                    else if (ah == 0x09 || ah == 0x0A) // Write Char/Attr
                    {
                        if (lastAxImm.HasValue) dbDesc += $" ; char='{(char)(lastAxImm.Value & 0xFF)}'";
                        dbDesc += " ; AL=char BH=page BL=attr CX=count";
                    }
                    else if (ah == 0x0C) // Write Pixel
                    {
                        if (lastAl.HasValue) dbDesc += $" ; color={lastAl.Value}";
                        dbDesc += " ; AL=color BH=page CX=x DX=y";
                    }
                    else if (ah == 0x0D) // Read Pixel
                    {
                        dbDesc += " ; BH=page CX=x DX=y (returns AL=color)";
                    }
                    else if (ah == 0x0F) // Get Mode
                    {
                        dbDesc += " ; (returns AL=mode AH=cols BH=page)";
                    }
                    else if (ah == 0x13) // Write String
                    {
                        dbDesc += " ; AL=mode BH=page BL=attr CX=len DX=row/col ES:BP=string";
                    }
                }

                // BIOS Disk
                if (intNo == 0x13 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x02 || ah == 0x03) // Read/Write sectors
                    {
                        if (lastAl.HasValue) dbDesc += $" ; count={lastAl.Value}";
                        if (lastDxImm.HasValue) dbDesc += $" ; drive=0x{(lastDxImm.Value & 0xFF):X} head={lastDxImm.Value >> 8}";
                        dbDesc += " ; AL=count CH=cyl CL=sec DH=head DL=drive ES:BX=buffer";
                    }
                }

                // BIOS Serial
                if (intNo == 0x14) dbDesc += " ; AH=0:Init AH=1:Send AH=2:Recv AH=3:Status ; DX=port";

                // BIOS System
                if (intNo == 0x15 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x86) dbDesc += " ; Wait (CX:DX=microseconds)";
                    else if (ah == 0x87) dbDesc += " ; Move Extended Block (CX=words ES:SI=GDT)";
                    else if (ah == 0x88) dbDesc += " ; Get Extended Memory Size";
                    else if (ah == 0xC0) dbDesc += " ; Get System Config (returns ES:BX -> table)";
                    else if (lastAxImm == 0xE801) dbDesc += " ; Get Ext Memory (AX=1-16MB BX=>16MB)";
                    else if (lastAxImm == 0xE820) dbDesc += " ; Get Memory Map (EAX=E820 EDX=SMAP ES:DI=buf)";
                    else if (lastAxImm == 0x5300) dbDesc += " ; APM: Check Presence";
                }

                // BIOS Keyboard/Timer/System
                if (intNo == 0x16) dbDesc += " ; AH=0:Get AH=1:Peek AH=2:ShiftFlags";
                if (intNo == 0x17) dbDesc += " ; AH=0:Print AH=1:Init AH=2:Status ; DX=port";
                if (intNo == 0x1A) dbDesc += " ; AH=0:GetTicks AH=1:SetTicks AH=2:GetTime AH=4:GetDate";

                // Multiplex
                if (intNo == 0x2F && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x15) // MSCDEX
                    {
                        var al = lastAl ?? (byte)(lastAxImm ?? 0);
                        var sub = al switch
                        {
                            0x00 => "CheckPresence",
                            0x0B => "GetDriveList",
                            0x0C => "GetVersion",
                            0x10 => "GetDeviceInfo",
                            _ => $"MSCDEX sub=0x{al:X2}"
                        };
                        dbDesc += $" ; {sub}";
                    }
                    else if (lastAxImm.HasValue)
                    {
                        var ax = lastAxImm.Value;
                        if (ax == 0x1680) dbDesc += " ; DPMI: release time slice";
                        else if (ax == 0x1687) dbDesc += " ; DPMI: get entry point";
                        else if (ax == 0x1689) dbDesc += " ; DPMI: get version";
                        else if (ax == 0x4300) dbDesc += " ; XMS: check presence";
                        else if (ax == 0x4310) dbDesc += " ; XMS: get entry point";
                        else if (ah == 0x11) dbDesc += " ; Network: redirector (AL=func)";
                        else if (ah == 0x12) dbDesc += " ; DOS: internal services (AL=func)";
                        else if (ax == 0x1600) dbDesc += " ; Windows: check presence (enhanced mode)";
                        else if (ax == 0x4A11) dbDesc += " ; DoubleSpace: check presence";
                    }
                }

                // DPMI extra
                if (intNo == 0x31 && lastAxImm.HasValue)
                {
                    var ax = lastAxImm.Value;
                    if (ax == 0x0100) dbDesc += $" ; BX={lastBxImm}p ({lastBxImm * 16}b)";
                    if (ax == 0x0501) dbDesc += $" ; size={((uint)(lastBxImm ?? 0) << 16) | (lastCxImm ?? 0)}b";
                }

                // Mouse extra
                if (intNo == 0x33 && lastAxImm.HasValue)
                {
                    var ax = lastAxImm.Value;
                    if (ax == 0x0004) dbDesc += $" ; X={lastCxImm} Y={lastDxImm}";
                }

                return dbDesc;
            }

            // Opt-in: record unknown interrupt usage for building local packs.
            UnknownInterruptRecorder.Record(intNo, lastAh, null);

            if (intNo == 0x21)
            {
                if (!lastAh.HasValue)
                    return "INT 21h";

                var ah = lastAh.Value;
                switch (ah)
                {
                    case 0x09:
                    {
                        // Print string at DS:DX ($-terminated)
                        if (lastDxImm.HasValue)
                        {
                            var dx = (uint)lastDxImm.Value;
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + dx) : dx;
                            if (stringSyms != null && stringSyms.TryGetValue(linear, out var sym))
                            {
                                var prev = stringPrev != null && stringPrev.TryGetValue(linear, out var p) ? p : string.Empty;
                                if (!string.IsNullOrEmpty(prev))
                                    return $"DOS21h/09h print $ {sym} (DX=0x{dx:X}) \"{prev}\"";
                                return $"DOS21h/09h print $ {sym} (DX=0x{dx:X})";
                            }
                            return $"DOS21h/09h print $ at DS:DX (DX=0x{dx:X}, linear=0x{linear:X})";
                        }
                        return "DOS21h/09h print $ at DS:DX";
                    }
                    case 0x4C:
                        return "DOS21h/4Ch terminate (AL=exit code)";
                    case 0x30:
                        return "DOS21h/30h get DOS version";
                    case 0x3D:
                        return "DOS21h/3Dh open file";
                    case 0x3F:
                        return "DOS21h/3Fh read file/device";
                    case 0x40:
                        return "DOS21h/40h write file/device";
                    case 0x48:
                        return "DOS21h/48h allocate memory";
                    case 0x4A:
                        return "DOS21h/4Ah resize memory block";
                    default:
                        return $"INT 21h AH=0x{ah:X2}";
                }
            }

            if (intNo == 0x10)
            {
                if (!lastAh.HasValue)
                    return "INT 10h";
                return $"INT 10h AH=0x{lastAh.Value:X2} (BIOS video)";
            }

            return $"INT 0x{intNo:X2}";
        }

        private static string TryReadAsciiString(byte[] module, uint linear, int maxLen)
        {
            if (module == null || maxLen <= 0)
                return string.Empty;

            if (linear >= (uint)module.Length)
                return string.Empty;

            var start = (int)linear;
            var end = Math.Min(module.Length, start + maxLen);
            var sb = new StringBuilder();

            for (var i = start; i < end; i++)
            {
                var b = module[i];
                if (b == 0x00)
                    break;

                // Keep this conservative to avoid random binary junk.
                if (b < 0x20 || b > 0x7E)
                    return string.Empty;

                sb.Append((char)b);
            }

            var s = sb.ToString().Trim();
            if (s.Length == 0)
                return string.Empty;

            return s.Replace("\"", "\\\"");
        }

        private static string TryReadDollarString(byte[] module, uint linear, int maxLen)
        {
            if (module == null || maxLen <= 0)
                return string.Empty;

            if (linear >= (uint)module.Length)
                return string.Empty;

            var start = (int)linear;
            var end = Math.Min(module.Length, start + maxLen);
            var sb = new StringBuilder();

            for (var i = start; i < end; i++)
            {
                var b = module[i];
                if (b == (byte)'$')
                    break;
                if (b == 0x00)
                    return string.Empty;

                if (b < 0x20 || b > 0x7E)
                    return string.Empty;

                sb.Append((char)b);
            }

            var s = sb.ToString();
            if (s.Length == 0)
                return string.Empty;

            return s.Replace("\"", "\\\"");
        }

        internal static string TryFormatFcbDetail(uint? lastImm, byte[] module)
        {
            if (!lastImm.HasValue || module == null)
                return string.Empty;

            var addr = lastImm.Value;
            if (addr + 12 > module.Length)
                return string.Empty;

            // Offset 0: Drive (0=default, 1=A, 2=B, 3=C)
            var drive = module[addr];
            var name = Encoding.ASCII.GetString(module, (int)addr + 1, 8).TrimEnd();
            var ext = Encoding.ASCII.GetString(module, (int)addr + 9, 3).TrimEnd();

            if (string.IsNullOrEmpty(name))
                return string.Empty;

            // Check if it looks like a valid filename (all printable)
            if (name.Any(c => c < 0x20 || c > 0x7E) || ext.Any(c => c < 0x20 || c > 0x7E))
                return string.Empty;

            var driveStr = drive switch
            {
                0 => "",
                1 => "A:",
                2 => "B:",
                3 => "C:",
                _ => $"{(char)('A' + drive - 1)}:"
            };

            var filename = name;
            if (!string.IsNullOrEmpty(ext))
                filename += "." + ext;

            return $"FCB=0x{addr:X} [{driveStr}{filename}]";
        }

        private static string TryFormatPointerDetail(ushort? lastImm, ushort? lastDsImm, string regName, Dictionary<uint, string> stringSyms, Dictionary<uint, string> stringPrev)
        {
            if (!lastImm.HasValue)
                return string.Empty;

            var val = (uint)lastImm.Value;
            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + val) : val;

            if (stringSyms != null && stringSyms.TryGetValue(linear, out var sym))
            {
                var prev = stringPrev != null && stringPrev.TryGetValue(linear, out var p) ? p : string.Empty;
                var detail = lastDsImm.HasValue ? $"{regName}=0x{val:X} (lin 0x{linear:X}) -> {sym}" : $"{regName}={sym}";
                if (!string.IsNullOrEmpty(prev))
                    return $"{detail} \"{prev}\"";
                return detail;
            }

            if (stringPrev != null && stringPrev.TryGetValue(linear, out var onlyPrev) && !string.IsNullOrEmpty(onlyPrev))
            {
                var detail = lastDsImm.HasValue ? $"{regName}=0x{val:X} (lin 0x{linear:X})" : $"{regName}=0x{val:X}";
                return $"{detail} \"{onlyPrev}\"";
            }

            if (lastDsImm.HasValue)
                return $"{regName}=0x{val:X} (lin 0x{linear:X})";

            return $"{regName}=0x{val:X}";
        }
    }
}
