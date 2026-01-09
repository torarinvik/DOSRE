using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string TryAnnotateArithmeticIdioms(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            if (TryAnnotateMulByConstShort(instructions, idx, out var hint))
                return hint;
            if (TryAnnotateMulByConst171(instructions, idx, out hint))
                return hint;
            if (TryAnnotateFixedPointMulRound16(instructions, idx, out hint))
                return hint;
            if (TryAnnotateSignedDiv(instructions, idx, out hint))
                return hint;

            return string.Empty;
        }

        private static bool TryParseMovClFromIndexByte(string insText, out string indexReg, out int scale, out uint disp)
        {
            indexReg = null;
            scale = 0;
            disp = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Example: mov cl, [edi*4+0x1]
            var m = Regex.Match(insText.Trim(), @"^mov\s+cl,\s*\[(?<idx>e[a-z]{2})\*(?<scale>\d+)\+0x(?<disp>[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            indexReg = m.Groups["idx"].Value.ToLowerInvariant();
            if (!int.TryParse(m.Groups["scale"].Value, out scale) || scale <= 0)
                return false;
            if (!TryParseHexOrDecUInt32(m.Groups["disp"].Value, out disp))
                return false;
            return true;
        }

        private static bool TryParseMovEaxFromTableLookup(string insText, out string tableBaseReg, out string indexReg, out int scale, out uint disp)
        {
            tableBaseReg = null;
            indexReg = null;
            scale = 0;
            disp = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Example: mov eax, [edx+ecx*4+0x10b08]
            var m = Regex.Match(insText.Trim(), @"^mov\s+eax,\s*\[(?<base>e[a-z]{2})\+(?<idx>e[a-z]{2})\*(?<scale>\d+)\+0x(?<disp>[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            tableBaseReg = m.Groups["base"].Value.ToLowerInvariant();
            indexReg = m.Groups["idx"].Value.ToLowerInvariant();
            if (!int.TryParse(m.Groups["scale"].Value, out scale) || scale <= 0)
                return false;
            if (!TryParseHexOrDecUInt32(m.Groups["disp"].Value, out disp))
                return false;
            return true;
        }

        private static bool TryParseAddMemEbpDispEax(string insText, out uint disp)
        {
            disp = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Example: add [ds:ebp+0x311c8], eax
            var m = Regex.Match(insText.Trim(), @"^add\s+\[(?:ds:)?ebp\+0x(?<disp>[0-9A-Fa-f]+)\]\s*,\s*eax\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            return TryParseHexOrDecUInt32(m.Groups["disp"].Value, out disp);
        }

        private static string TryAnnotateByteTableAccumulationUnroll(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern (common in the big uncommented block):
            //   mov cl, [idx*4+off]
            //   mov eax, [tbl + ecx*4 + base]
            //   add [ds:ebp + accDisp], eax
            // Emit hint on the ADD line to keep noise down while breaking long runs.
            var insText = instructions[idx].ToString();
            if (!TryParseAddMemEbpDispEax(insText, out var accDisp))
                return string.Empty;

            if (idx < 2)
                return string.Empty;

            var prev1 = instructions[idx - 1].ToString();
            var prev2 = instructions[idx - 2].ToString();

            if (!TryParseMovEaxFromTableLookup(prev1, out var tableReg, out var tableIdxReg, out var tableScale, out var tableDisp))
                return string.Empty;

            // Expect the index to be in ECX (cl) for this idiom.
            if (!tableIdxReg.Equals("ecx", StringComparison.OrdinalIgnoreCase) || tableScale != 4)
                return string.Empty;

            if (!TryParseMovClFromIndexByte(prev2, out var srcIdxReg, out var srcScale, out var srcDisp))
                return string.Empty;

            var srcExpr = $"byte([{srcIdxReg}*{srcScale}+0x{srcDisp:X}])";
            var tblExpr = $"[{tableReg}+0x{tableDisp:X} + ecx*4]";
            return $"HINT: acc[ebp+0x{accDisp:X}] += {tblExpr}[{srcExpr}]";
        }

        private static string TryAnnotateAddAdc64Advance(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx <= 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern: add loReg, [abs] ; adc hiReg, [abs]
            var a = instructions[idx - 1].ToString().Trim();
            var b = instructions[idx].ToString().Trim();

            var ma = Regex.Match(a, @"^add\s+(?<lo>e[a-z]{2})\s*,\s*\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*$", RegexOptions.IgnoreCase);
            var mb = Regex.Match(b, @"^adc\s+(?<hi>e[a-z]{2})\s*,\s*\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*$", RegexOptions.IgnoreCase);
            if (!ma.Success || !mb.Success)
                return string.Empty;

            var lo = ma.Groups["lo"].Value.ToLowerInvariant();
            var hi = mb.Groups["hi"].Value.ToLowerInvariant();
            var absLoTok = ma.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
            var absHiTok = mb.Groups["abs"].Value.Trim().TrimEnd('h', 'H');

            if (!TryParseHexOrDecUInt32(absLoTok, out var absLo))
                return string.Empty;
            if (!TryParseHexOrDecUInt32(absHiTok, out var absHi))
                return string.Empty;

            return $"HINT: advance {hi}:{lo} += [0x{absHi:X}]:[0x{absLo:X}] (adc chain)";
        }

        private static string TryAnnotateSuspectDataDecode(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            static bool IsAddEaxEax(string t)
                => t != null && t.Trim().Equals("add [eax], eax", StringComparison.OrdinalIgnoreCase);

            static bool IsWeirdPrivOrSeg(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;
                var s = t.Trim();
                if (s.Equals("invalid", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (s.Equals("iretd", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (s.StartsWith("pop ", StringComparison.OrdinalIgnoreCase) || s.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                {
                    if (s.EndsWith(" ds", StringComparison.OrdinalIgnoreCase) || s.EndsWith(" ss", StringComparison.OrdinalIgnoreCase) || s.EndsWith(" es", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                if (s.Equals("das", StringComparison.OrdinalIgnoreCase) || s.Equals("arpl", StringComparison.OrdinalIgnoreCase))
                    return true;
                return false;
            }

            const int window = 48;
            var lo = Math.Max(0, idx - window);
            var hi = Math.Min(instructions.Count - 1, idx + window);
            var add0100 = 0;
            var weird = 0;

            for (var i = lo; i <= hi; i++)
            {
                var t = instructions[i].ToString();
                if (IsAddEaxEax(t)) add0100++;
                if (IsWeirdPrivOrSeg(t)) weird++;
            }

            if (add0100 < 8 && (add0100 < 5 || weird < 3))
                return string.Empty;

            var cur = instructions[idx].ToString();
            if (IsAddEaxEax(cur))
                return "NOTE: suspicious decode (repeated 0x0100 pattern) — likely data, not code";

            if (IsWeirdPrivOrSeg(cur))
                return "NOTE: suspicious decode (rare/privileged op) — likely data, not code";

            return string.Empty;
        }

        private static bool TryAnnotateMulByConstShort(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (idx < 1)
                return false;

            var cur = instructions[idx].ToString().Trim();
            var mCur = Regex.Match(cur, @"^\s*add\s+(?<dst>e[a-d]x|e[sdi]i|e[bp]p)\s*,\s*(?<src>e[a-d]x|e[sdi]i|e[bp]p)\s*$", RegexOptions.IgnoreCase);
            if (!mCur.Success)
                return false;

            var dst = mCur.Groups["dst"].Value.ToLowerInvariant();
            var src2 = mCur.Groups["src"].Value.ToLowerInvariant();
            if (dst != src2)
                return false;

            string src = null;
            int? scale = null;
            var foundAdd = false;

            for (var back = 1; back <= 4 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();

                if (!foundAdd)
                {
                    var mAdd = Regex.Match(t, $@"^\s*add\s+{Regex.Escape(dst)}\s*,\s*(?<src>e[a-d]x|e[sdi]i|e[bp]p)\s*$", RegexOptions.IgnoreCase);
                    if (mAdd.Success)
                    {
                        var s = mAdd.Groups["src"].Value.ToLowerInvariant();
                        if (s == dst)
                            return false;
                        src = s;
                        foundAdd = true;
                        continue;
                    }
                }
                else
                {
                    var mLea = Regex.Match(t, $@"^\s*lea\s+{Regex.Escape(dst)}\s*,\s*\[{Regex.Escape(src)}\*(?<scale>2|4|8)\]\s*$", RegexOptions.IgnoreCase);
                    if (mLea.Success)
                    {
                        if (int.TryParse(mLea.Groups["scale"].Value, out var sc) && (sc == 2 || sc == 4 || sc == 8))
                            scale = sc;
                        break;
                    }
                }

                if (Regex.IsMatch(t, $@"^\s*(mov|lea|add|sub|xor|and|or|shl|shr|sar|imul)\s+{Regex.Escape(dst)}\b", RegexOptions.IgnoreCase))
                    return false;
            }

            if (!foundAdd || !scale.HasValue)
                return false;

            var mul = (scale.Value + 1) * 2;
            hint = $"HINT: {dst} = {src}*{mul}";
            return true;
        }

        private static bool TryAnnotateMulByConst171(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (idx < 6)
                return false;

            var i0 = instructions[idx].ToString().Trim();
            var i1 = instructions[idx - 1].ToString().Trim();
            var i2 = instructions[idx - 2].ToString().Trim();
            var i3 = instructions[idx - 3].ToString().Trim();
            var i4 = instructions[idx - 4].ToString().Trim();
            var i5 = instructions[idx - 5].ToString().Trim();
            var i6 = instructions[idx - 6].ToString().Trim();

            if (!Regex.IsMatch(i0, @"^\s*add\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i1, @"^\s*shl\s+eax\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i2, @"^\s*mov\s+edx\s*,\s*eax\s*$", RegexOptions.IgnoreCase))
                return false;

            var mSub = Regex.Match(i3, @"^\s*sub\s+eax\s*,\s*(?<src>e[a-d]x|e[sdi]i|e[bp]p)\s*$", RegexOptions.IgnoreCase);
            if (!mSub.Success)
                return false;
            var src = mSub.Groups["src"].Value.ToLowerInvariant();

            if (!Regex.IsMatch(i4, @"^\s*shl\s+eax\s*,\s*(?:0x)?2\s*$", RegexOptions.IgnoreCase))
                return false;

            var mAdd = Regex.Match(i5, @"^\s*add\s+eax\s*,\s*(?<src>e[a-d]x|e[sdi]i|e[bp]p)\s*$", RegexOptions.IgnoreCase);
            if (!mAdd.Success)
                return false;
            if (!string.Equals(src, mAdd.Groups["src"].Value, StringComparison.OrdinalIgnoreCase))
                return false;

            var mLea = Regex.Match(i6, @"^\s*lea\s+eax\s*,\s*\[(?<src>e[a-d]x|e[sdi]i|e[bp]p)\*(?<scale>2|4|8)\]\s*$", RegexOptions.IgnoreCase);
            if (!mLea.Success)
                return false;
            if (!string.Equals(src, mLea.Groups["src"].Value, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!int.TryParse(mLea.Groups["scale"].Value, out var scale) || scale != 4)
                return false;

            hint = $"HINT: eax = {src}*171";
            return true;
        }

        private static bool TryAnnotateFixedPointMulRound16(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (idx < 3)
                return false;

            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^\s*shrd\s+eax\s*,\s*edx\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase))
                return false;

            var i1 = instructions[idx - 1].ToString().Trim();
            var i2 = instructions[idx - 2].ToString().Trim();
            var i3 = instructions[idx - 3].ToString().Trim();

            if (!Regex.IsMatch(i1, @"^\s*adc\s+edx\s*,\s*(?:0x)?0\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i2, @"^\s*add\s+eax\s*,\s*(?:0x)?8000\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i3, @"^\s*imul\s+edx\s*$", RegexOptions.IgnoreCase))
                return false;

            hint = "HINT: eax = (eax*edx + 0x8000) >> 16 (mul+round)";
            return true;
        }

        private static bool TryAnnotateSignedDiv(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (idx < 1)
                return false;

            var i0 = instructions[idx].ToString().Trim();
            var m = Regex.Match(i0, @"^\s*idiv\s+(?<div>e[a-d]x|e[sdi]i|e[bp]p|dword\s+\[[^\]]+\])\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var div = m.Groups["div"].Value.Trim();

            for (var back = 1; back <= 3 && idx - back >= 0; back++)
            {
                var p = instructions[idx - back].ToString().Trim();
                if (p.Equals("cdq", StringComparison.OrdinalIgnoreCase))
                {
                    hint = $"HINT: signed div by {div} (eax=quot, edx=rem)";
                    return true;
                }

                if (Regex.IsMatch(p, @"^\s*(mov|lea|add|sub|xor|and|or|shl|shr|sar|imul)\s+edx\b", RegexOptions.IgnoreCase))
                    break;
            }

            var sarIdx = -1;
            for (var back = 1; back <= 4 && idx - back >= 0; back++)
            {
                var p = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(p, @"^\s*sar\s+edx\s*,\s*(?:0x)?1f\s*$", RegexOptions.IgnoreCase))
                {
                    sarIdx = idx - back;
                    break;
                }

                if (Regex.IsMatch(p, @"^\s*(mov|lea|add|sub|xor|and|or|shl|shr|sar|imul)\s+edx\b", RegexOptions.IgnoreCase))
                    return false;
            }

            if (sarIdx >= 1)
            {
                for (var back = 1; back <= 4 && sarIdx - back >= 0; back++)
                {
                    var p = instructions[sarIdx - back].ToString().Trim();
                    if (Regex.IsMatch(p, @"^\s*mov\s+edx\s*,\s*eax\s*$", RegexOptions.IgnoreCase))
                    {
                        hint = $"HINT: signed div by {div} (eax=quot, edx=rem)";
                        return true;
                    }

                    if (Regex.IsMatch(p, @"^\s*(mov|lea|add|sub|xor|and|or|shl|shr|sar|imul)\s+edx\b", RegexOptions.IgnoreCase))
                        return false;
                }
            }

            return false;
        }
    }
}
