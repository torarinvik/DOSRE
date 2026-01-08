using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Analysis;
using SharpDisasm;

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
            ushort? lastDxImm = null;
            FunctionInfo currentFunc = null;
            foreach (var ins in instructions)
            {
                var addr = (uint)ins.Offset;

                if (mzInsights && functionStarts.Contains(addr))
                {
                    sb.AppendLine();
                    sb.AppendLine($"func_{addr:X5}:");
                    if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                        sb.AppendLine($"; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X}"))}");

                    currentFunc = funcInfos.TryGetValue(addr, out var fi) ? fi : null;
                    lastAh = null;
                    lastDxImm = null;

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
                    UpdateSimpleDosState(ins, ref lastAh, ref lastDxImm);
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
                    var hint = TryDecodeInterruptHint(ins, lastAh, lastDxImm, stringSyms, stringPrev);
                    if (!string.IsNullOrEmpty(hint))
                        insText += $" ; {hint}";
                }

                sb.AppendLine($"{addr:X5}h {bytes.PadRight(16, ' ')} {insText}");
            }

            output = sb.ToString();
            return true;
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

        private static void UpdateSimpleDosState(Instruction ins, ref byte? lastAh, ref ushort? lastDxImm)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return;

            // mov ah, imm8: B4 ib
            if (b[0] == 0xB4 && b.Length >= 2)
            {
                lastAh = b[1];
                return;
            }

            // mov dx, imm16: BA iw
            if (b[0] == 0xBA && b.Length >= 3)
            {
                lastDxImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }
        }

        private static string TryDecodeInterruptHint(
            Instruction ins,
            byte? lastAh,
            ushort? lastDxImm,
            Dictionary<uint, string> stringSyms,
            Dictionary<uint, string> stringPrev)
        {
            var b = ins.Bytes;
            if (b == null || b.Length < 2)
                return string.Empty;

            // int imm8: CD ib
            if (b[0] != 0xCD)
                return string.Empty;

            var intNo = b[1];

            // Prefer database-driven descriptions.
            // For MZ we only track AH (8-bit) today; AX is unknown in this quick tracker.
            string dbDesc;
            if (DosInterruptDatabase.Instance.TryDescribe(intNo, lastAh, null, out dbDesc) && !string.IsNullOrEmpty(dbDesc))
            {
                // Preserve the richer inline-string detail for DOS print-$.
                if (intNo == 0x21 && lastAh.HasValue && lastAh.Value == 0x09)
                {
                    if (lastDxImm.HasValue)
                    {
                        var dx = (uint)lastDxImm.Value;
                        if (stringSyms != null && stringSyms.TryGetValue(dx, out var sym))
                        {
                            var prev = stringPrev != null && stringPrev.TryGetValue(dx, out var p) ? p : string.Empty;
                            if (!string.IsNullOrEmpty(prev))
                                return dbDesc + $" ; DX={sym} \"{prev}\"";
                            return dbDesc + $" ; DX={sym}";
                        }
                        return dbDesc + $" ; DX=0x{dx:X}";
                    }
                }

                return dbDesc;
            }

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
                            if (stringSyms != null && stringSyms.TryGetValue(dx, out var sym))
                            {
                                var prev = stringPrev != null && stringPrev.TryGetValue(dx, out var p) ? p : string.Empty;
                                if (!string.IsNullOrEmpty(prev))
                                    return $"DOS21h/09h print $ {sym} (DX=0x{dx:X}) \"{prev}\"";
                                return $"DOS21h/09h print $ {sym} (DX=0x{dx:X})";
                            }
                            return $"DOS21h/09h print $ at DS:DX (DX=0x{dx:X})";
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
    }
}
