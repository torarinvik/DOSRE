using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Enums;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
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

        private static void TryAnalyzeFunctionMetaData(FunctionInfo info, List<Instruction> instructions)
        {
            for (var i = info.StartIndex; i < info.EndIndex; i++)
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

                if (!info.HasFrame) continue;

                var text = ins.ToString();
                // args: [bp+0xNN]
                foreach (Match m in Regex.Matches(text, @"\[bp\+0x(?<hex>[0-9a-fA-F]+)\]"))
                {
                    var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                    if (off >= 4 && off <= 0x80) info.ArgOffsets.Add(off);
                }
                foreach (Match m in Regex.Matches(text, @"\[bp\+(?<dec>\d+)\]"))
                {
                    var off = int.Parse(m.Groups["dec"].Value);
                    if (off >= 4 && off <= 0x80) info.ArgOffsets.Add(off);
                }

                // locals: [bp-0xNN]
                foreach (Match m in Regex.Matches(text, @"\[bp\-0x(?<hex>[0-9a-fA-F]+)\]"))
                {
                    var off = Convert.ToInt32(m.Groups["hex"].Value, 16);
                    if (off >= 2 && off <= 0x200) info.LocalOffsets.Add(off);
                }
                foreach (Match m in Regex.Matches(text, @"\[bp\-(?<dec>\d+)\]"))
                {
                    var off = int.Parse(m.Groups["dec"].Value);
                    if (off >= 2 && off <= 0x200) info.LocalOffsets.Add(off);
                }
            }
        }

        private static void UpdateStackState(
            Instruction ins, int i, List<Instruction> instructions,
            ref bool esIsSs, ref int esSavedAsSsDepth, ref sbyte? lastBxBpDisp8, ref string lastLdsSiBaseSym,
            Dictionary<sbyte, ushort> bpFrameWords, Dictionary<sbyte, string> bpFrameSyms,
            ushort? lastAxImm, ushort? lastCxImm, ushort? lastDxImm, ushort? lastBxImm, ushort? lastSiImm, ushort? lastDiImm,
            ushort? lastDsImm, ushort? lastEsImm)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0) return;

            // Track ES==SS via push/pop patterns
            if (b.Length >= 1 && b[0] == 0x16) { /* push ss */ }
            else if (b.Length >= 1 && b[0] == 0x06) { if (esIsSs) esSavedAsSsDepth++; }
            else if (b.Length >= 1 && b[0] == 0x07) { if (esSavedAsSsDepth > 0) { esSavedAsSsDepth--; esIsSs = true; } }

            // mov sreg, r/m16 (0x8E /r)
            if (b.Length >= 2 && b[0] == 0x8E)
            {
                var reg = (b[1] >> 3) & 0x07;
                if (reg == 0) esIsSs = false; // ES
            }

            // push ss; pop es => ES=SS
            if (b.Length >= 1 && b[0] == 0x07 && i > 0)
            {
                var pb = instructions[i - 1].Bytes;
                if (pb != null && pb.Length >= 1 && pb[0] == 0x16) esIsSs = true;
            }

            // lea bx, [bp+disp8] : 8D 5E ib
            if (b.Length >= 3 && b[0] == 0x8D && b[1] == 0x5E) lastBxBpDisp8 = unchecked((sbyte)b[2]);

            // lds si, [bp+disp8] : C5 76 ib
            if (b.Length >= 3 && b[0] == 0xC5)
            {
                var modrm = b[1];
                var mod = (modrm >> 6) & 0x03;
                var reg = (modrm >> 3) & 0x07;
                var rm = modrm & 0x07;
                if (reg == 6 && rm == 6) // SI, [BP+disp]
                {
                    if (mod == 0x01) lastLdsSiBaseSym = $"[BP{(unchecked((sbyte)b[2]) >= 0 ? "+" : "")}{unchecked((sbyte)b[2])}]";
                    else if (mod == 0x02 && b.Length >= 4) { lastLdsSiBaseSym = $"[BP{((short)(b[2] | (b[3] << 8)) >= 0 ? "+" : "")}{(short)(b[2] | (b[3] << 8))}]"; }
                }
            }

            if (b.Length >= 1 && (b[0] == 0xBB || (b[0] == 0x89 && b.Length >= 2 && b[1] == 0xC3) || (b[0] == 0x8B && b.Length >= 2 && b[1] == 0xD8)))
            {
                if (!(b.Length >= 3 && b[0] == 0x8D && b[1] == 0x5E)) lastBxBpDisp8 = null;
            }

            // mov word [bp+disp8], imm16 : C7 46 ib iw
            if (b.Length >= 5 && b[0] == 0xC7 && b[1] == 0x46)
            {
                var disp = unchecked((sbyte)b[2]);
                bpFrameWords[disp] = (ushort)(b[3] | (b[4] << 8));
                bpFrameSyms.Remove(disp);
            }

            // mov [bp+disp8], reg16 : 89 46 ib
            if (b.Length >= 3 && b[0] == 0x89 && b[1] >= 0x46 && b[1] <= 0x7E)
            {
                var modrm = b[1];
                var mod = (modrm >> 6) & 0x03;
                var reg = (modrm >> 3) & 0x07;
                var rm = modrm & 0x07;
                if (mod == 0x01 && rm == 0x06)
                {
                    var disp = unchecked((sbyte)b[2]);
                    ushort? src = reg switch { 0 => lastAxImm, 1 => lastCxImm, 2 => lastDxImm, 3 => lastBxImm, 6 => lastSiImm, 7 => lastDiImm, _ => null };
                    if (src.HasValue) { bpFrameWords[disp] = src.Value; bpFrameSyms.Remove(disp); }
                    else
                    {
                        var regName = reg switch { 0 => "AX", 1 => "CX", 2 => "DX", 3 => "BX", 6 => "SI", 7 => "DI", _ => "?" };
                        if (reg == 6 && !string.IsNullOrEmpty(lastLdsSiBaseSym)) bpFrameSyms[disp] = $"off({lastLdsSiBaseSym})";
                        else bpFrameSyms[disp] = regName;
                    }
                }
            }

            // mov [bp+disp8], ds/es : 8C 5E ib (ds), 8C 46 ib (es)
            if (b.Length >= 3 && b[0] == 0x8C)
            {
                var disp = unchecked((sbyte)b[2]);
                if (b[1] == 0x5E) // ds
                {
                    if (lastDsImm.HasValue) { bpFrameWords[disp] = lastDsImm.Value; bpFrameSyms.Remove(disp); }
                    else bpFrameSyms[disp] = !string.IsNullOrEmpty(lastLdsSiBaseSym) ? $"seg({lastLdsSiBaseSym})" : "DS";
                }
                else if (b[1] == 0x46) // es
                {
                    if (lastEsImm.HasValue) { bpFrameWords[disp] = lastEsImm.Value; bpFrameSyms.Remove(disp); }
                    else bpFrameSyms[disp] = esIsSs ? "SS" : "ES";
                }
            }
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

            string[] needles = hint switch
            {
                EnumToolchainHint.Borland => new[] { "Borland", "Turbo C", "Turbo Pascal", "TC++", "TURBO" },
                EnumToolchainHint.Watcom => new[] { "WATCOM", "Watcom" },
                _ => Array.Empty<string>()
            };

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
            if (maxHits <= 0 || data == null || data.Length == 0 || string.IsNullOrEmpty(needle))
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
                    if (data[i + j] != nb[j]) { ok = false; break; }
                }

                if (!ok) continue;

                yield return i;
                hits++;
                if (hits >= maxHits) yield break;
                i += nb.Length - 1;
            }
        }

        private static bool TryGetRelativeBranchTarget16(Instruction ins, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return false;

            var op0 = b[0];
            var baseOff = (uint)ins.Offset;

            if (op0 == 0xE8 && b.Length >= 3)
            {
                isCall = true;
                var rel = (short)(b[1] | (b[2] << 8));
                var t = (int)baseOff + b.Length + rel;
                if (t >= 0) { target = (uint)t; return true; }
            }

            if (op0 == 0xE9 && b.Length >= 3)
            {
                var rel = (short)(b[1] | (b[2] << 8));
                var t = (int)baseOff + b.Length + rel;
                if (t >= 0) { target = (uint)t; return true; }
            }

            if (op0 == 0xEB && b.Length >= 2)
            {
                var rel = (sbyte)b[1];
                var t = (int)baseOff + b.Length + rel;
                if (t >= 0) { target = (uint)t; return true; }
            }

            if (op0 >= 0x70 && op0 <= 0x7F && b.Length >= 2)
            {
                var rel = (sbyte)b[1];
                var t = (int)baseOff + b.Length + rel;
                if (t >= 0) { target = (uint)t; return true; }
            }

            if (op0 == 0x0F && b.Length >= 4)
            {
                var op1 = b[1];
                if (op1 >= 0x80 && op1 <= 0x8F)
                {
                    var rel = (short)(b[2] | (b[3] << 8));
                    var t = (int)baseOff + b.Length + rel;
                    if (t >= 0) { target = (uint)t; return true; }
                }
            }

            return false;
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

                if (b.Length >= 2 && b[0] == 0xB4) ah = b[1];
                if (b.Length >= 2 && b[0] == 0xB0) al = b[1];
                if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xC0) al = 0;

                if (!filenameArgOff.HasValue && TryDecodeLdsDxFromBp(b, out var bpOff))
                    filenameArgOff = bpOff;
            }

            if (ah != 0x43 || al != 0x00)
                return string.Empty;
            if (!filenameArgOff.HasValue)
                return string.Empty;

            int? jccIdx = null;
            for (var i = idx + 1; i < Math.Min(scanEnd, idx + 8); i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length < 1) continue;
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
                if (b == null || b.Length == 0) continue;

                if (!outArgOff.HasValue && TryDecodeLesBxFromBp(b, out var bpOff))
                    outArgOff = bpOff;

                if (IsMovWordPtrEsBxFromCx(b))
                    sawStoreCx = true;

                if (b.Length >= 2 && b[0] == 0x33 && b[1] == 0xC0)
                    sawXorAxAx = true;
            }

            if (!outArgOff.HasValue || !sawStoreCx || !sawXorAxAx)
                return string.Empty;

            var failureReturnsOne = false;
            for (var i = idx + 1; i < scanEnd; i++)
            {
                var b = instructions[i].Bytes;
                if (b == null || b.Length == 0) continue;

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
            if (b == null || b.Length < 3) return false;
            if (b[0] != 0xC5) return false;

            var modrm = b[1];
            var mod = (modrm >> 6) & 0x3;
            var reg = (modrm >> 3) & 0x7;
            var rm = modrm & 0x7;

            if (reg != 0x2) return false;
            if (rm != 0x6) return false;

            if (mod == 0x1 && b.Length >= 3)
            {
                bpOff = unchecked((sbyte)b[2]);
                if (bpOff < 0) return false;
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
            if (b == null || b.Length < 3) return false;
            if (b[0] != 0xC4) return false;

            var modrm = b[1];
            var mod = (modrm >> 6) & 0x3;
            var reg = (modrm >> 3) & 0x7;
            var rm = modrm & 0x7;

            if (reg != 0x3) return false;
            if (rm != 0x6) return false;

            if (mod == 0x1 && b.Length >= 3)
            {
                bpOff = unchecked((sbyte)b[2]);
                if (bpOff < 0) return false;
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
            if (b == null || b.Length == 0) return false;
            if (b.Length >= 3 && b[0] == 0x26 && b[1] == 0x89 && b[2] == 0x0F) return true;
            if (b.Length >= 2 && b[0] == 0x89 && b[1] == 0x0F) return true;
            return false;
        }

        private static string TryReadAsciiStringFixed(byte[] module, uint linear, int length)
        {
            if (module == null || length <= 0) return string.Empty;
            if (linear >= (uint)module.Length) return string.Empty;

            var start = (int)linear;
            var end = Math.Min(module.Length, start + length);
            var sb = new StringBuilder();

            for (var i = start; i < end; i++)
            {
                var b = module[i];
                if (b == 0x00) break;
                if (b < 0x20 || b > 0x7E) return string.Empty;
                sb.Append((char)b);
            }

            var s = sb.ToString().Trim();
            if (s.Length == 0) return string.Empty;
            return s.Replace("\"", "\\\"");
        }

        private static string TryReadDosCommandTail(byte[] module, uint linear, int maxLen)
        {
            if (module == null || maxLen <= 0) return string.Empty;
            if (linear >= (uint)module.Length) return string.Empty;

            var start = (int)linear;
            if (start + 1 > module.Length) return string.Empty;

            var len = module[start];
            if (len == 0) return string.Empty;

            var readLen = Math.Min((int)len, maxLen);
            var end = Math.Min(module.Length, start + 1 + readLen);
            var sb = new StringBuilder();

            for (var i = start + 1; i < end; i++)
            {
                var b = module[i];
                if (b == 0x0D) break;
                if (b < 0x20 || b > 0x7E) return string.Empty;
                sb.Append((char)b);
            }

            var s = sb.ToString().Trim();
            if (s.Length == 0) return string.Empty;
            return s.Replace("\"", "\\\"");
        }

        private static string TryReadAsciiString(byte[] module, uint linear, int maxLen)
        {
            if (module == null || maxLen <= 0) return string.Empty;
            if (linear >= (uint)module.Length) return string.Empty;

            var start = (int)linear;
            var end = Math.Min(module.Length, start + maxLen);
            var sb = new StringBuilder();

            for (var i = start; i < end; i++)
            {
                var b = module[i];
                if (b == 0x00) break;
                if (b < 0x20 || b > 0x7E) return string.Empty;
                sb.Append((char)b);
            }

            var s = sb.ToString().Trim();
            if (s.Length == 0) return string.Empty;
            return s.Replace("\"", "\\\"");
        }

        private static string TryReadDollarString(byte[] module, uint linear, int maxLen)
        {
            if (module == null || maxLen <= 0) return string.Empty;
            if (linear >= (uint)module.Length) return string.Empty;

            var start = (int)linear;
            var end = Math.Min(module.Length, start + maxLen);
            var sb = new StringBuilder();

            for (var i = start; i < end; i++)
            {
                var b = module[i];
                if (b == (byte)'$') break;
                if (b == 0x00) return string.Empty;
                if (b < 0x20 || b > 0x7E) return string.Empty;
                sb.Append((char)b);
            }

            var s = sb.ToString();
            if (s.Length == 0) return string.Empty;
            return s.Replace("\"", "\\\"");
        }

        internal static string TryFormatFcbDetail(uint? lastImm, byte[] module)
        {
            if (!lastImm.HasValue || module == null) return string.Empty;

            var addr = lastImm.Value;
            if (addr + 12 > module.Length) return string.Empty;

            var drive = module[addr];
            var name = Encoding.ASCII.GetString(module, (int)addr + 1, 8).TrimEnd();
            var ext = Encoding.ASCII.GetString(module, (int)addr + 9, 3).TrimEnd();

            if (string.IsNullOrEmpty(name)) return string.Empty;
            if (name.Any(c => c < 0x20 || c > 0x7E) || ext.Any(c => c < 0x20 || c > 0x7E)) return string.Empty;

            var driveStr = drive switch { 0 => "", 1 => "A:", 2 => "B:", 3 => "C:", _ => $"{(char)('A' + drive - 1)}:" };
            var filename = name;
            if (!string.IsNullOrEmpty(ext)) filename += "." + ext;

            return $"FCB=0x{addr:X} [{driveStr}{filename}]";
        }

        private static string TryFormatPointerDetail(ushort? lastImm, ushort? lastDsImm, string regName, Dictionary<uint, string> stringSyms, Dictionary<uint, string> stringPrev)
        {
            if (!lastImm.HasValue) return string.Empty;

            var val = (uint)lastImm.Value;
            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + val) : val;

            if (stringSyms != null && stringSyms.TryGetValue(linear, out var sym))
            {
                var prev = stringPrev != null && stringPrev.TryGetValue(linear, out var p) ? p : string.Empty;
                var detail = lastDsImm.HasValue ? $"{regName}=0x{val:X} (lin 0x{linear:X}) -> {sym}" : $"{regName}={sym}";
                if (!string.IsNullOrEmpty(prev)) return $"{detail} \"{prev}\"";
                return detail;
            }

            if (stringPrev != null && stringPrev.TryGetValue(linear, out var onlyPrev) && !string.IsNullOrEmpty(onlyPrev))
            {
                var detail = lastDsImm.HasValue ? $"{regName}=0x{val:X} (lin 0x{linear:X})" : $"{regName}=0x{val:X}";
                return $"{detail} \"{onlyPrev}\"";
            }

            if (lastDsImm.HasValue) return $"{regName}=0x{val:X} (lin 0x{linear:X})";
            return $"{regName}=0x{val:X}";
        }
    }
}
