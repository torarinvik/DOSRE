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

            string hint;

            if (TryAnnotateMovEaxFromAbsScaled4(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMulBy1000ViaShifts(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMovEsi10ForDigitExtract(instructions, idx, out hint))
                return hint;
            if (TryAnnotateSignedDivBy10DigitSplit(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMulU8FromTwoMovzx(instructions, idx, out hint))
                return hint;
            if (TryAnnotateSar16BeforeImul(instructions, idx, out hint))
                return hint;
            if (TryAnnotateSar16ThenShlByCl(instructions, idx, out hint))
                return hint;
            if (TryAnnotateBitstreamExtractViaShr3AndShRD(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMulThenShRdEaxEdxByCl(instructions, idx, out hint))
                return hint;
            if (TryAnnotatePackHiByteWithLow24(instructions, idx, out hint))
                return hint;
            if (TryAnnotatePackStride4BytesIntoDword(instructions, idx, out hint))
                return hint;
            if (TryAnnotateShift16Add8000FlatPtr(instructions, idx, out hint))
                return hint;

            if (TryAnnotateImulImplicitEax64(instructions, idx, out hint))
                return hint;
            if (TryAnnotateFixedPointDivShift16(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMulByConstShort(instructions, idx, out hint))
                return hint;
            if (TryAnnotateMulByConst171(instructions, idx, out hint))
                return hint;
            if (TryAnnotateFixedPointMulRound16(instructions, idx, out hint))
                return hint;
            if (TryAnnotateSignedDiv(instructions, idx, out hint))
                return hint;
            if (TryAnnotateUnsignedDiv(instructions, idx, out hint))
                return hint;

            return string.Empty;
        }

        private static bool TryAnnotateSar16ThenShlByCl(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            // Pattern (e.g. loc_00080B86):
            //   sar r32, 0x10
            //   ...
            //   shl r32, cl
            // Often used as fixed-point scaling: ((x >> 16) << cl)
            var i0 = instructions[idx].ToString().Trim();
            var mSar = Regex.Match(i0, @"^sar\s+(?<reg>e[a-z]{2})\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase);
            if (!mSar.Success)
                return false;

            var reg = mSar.Groups["reg"].Value.ToLowerInvariant();

            var sawMovCl = false;
            for (var back = 1; back <= 3 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^mov\s+cl\s*,\s*[a-z]{2}\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, @"^mov\s+cl\s*,\s*\[.*\]\s*$", RegexOptions.IgnoreCase))
                {
                    sawMovCl = true;
                    break;
                }
            }

            for (var j = idx + 1; j < instructions.Count && j <= idx + 2; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, $@"^shl\s+{Regex.Escape(reg)}\s*,\s*cl\s*$", RegexOptions.IgnoreCase))
                {
                    hint = sawMovCl
                        ? "HINT: fixed-point scale: (x>>16) << cl"
                        : "HINT: (x>>16) << cl";
                    return true;
                }

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            return false;
        }

        private static bool TryAnnotateBitstreamExtractViaShr3AndShRD(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 5 || idx >= instructions.Count)
                return false;

            // Pattern (e.g. loc_00089F94):
            //   mov eax, <idx>
            //   mov ecx, <idx>
            //   shr eax, 0x3
            //   and ecx, 0x7
            //   mov eax, [eax+<base>]
            //   shrd eax, eax, cl
            // -> align bits from a packed bitstream (byteIndex=idx>>3, bitOffset=idx&7)
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^shrd\s+eax\s*,\s*eax\s*,\s*cl\s*$", RegexOptions.IgnoreCase))
                return false;

            var iPrev = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(iPrev, @"^mov\s+eax\s*,\s*\[eax\+(?<base>e[a-z]{2})\]\s*$", RegexOptions.IgnoreCase) &&
                !Regex.IsMatch(iPrev, @"^mov\s+eax\s*,\s*\[eax\+(?<base>e[a-z]{2})\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase))
            {
                return false;
            }

            var i2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(i2, @"^and\s+ecx\s*,\s*(?:0x)?7\s*$", RegexOptions.IgnoreCase))
                return false;

            var i3 = instructions[idx - 3].ToString().Trim();
            if (!Regex.IsMatch(i3, @"^shr\s+eax\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return false;

            var i4 = instructions[idx - 4].ToString().Trim();
            var i5 = instructions[idx - 5].ToString().Trim();
            if (!Regex.IsMatch(i4, @"^mov\s+ecx\s*,\s*e[a-z]{2}\s*$", RegexOptions.IgnoreCase))
                return false;

            var mMovEax = Regex.Match(i5, @"^mov\s+eax\s*,\s*(?<idx>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            var mMovEcx = Regex.Match(i4, @"^mov\s+ecx\s*,\s*(?<idx>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!mMovEax.Success || !mMovEcx.Success)
                return false;

            if (!mMovEax.Groups["idx"].Value.Equals(mMovEcx.Groups["idx"].Value, StringComparison.OrdinalIgnoreCase))
                return false;

            hint = "HINT: bitstream extract (byte=idx>>3, bit=idx&7)";
            return true;
        }

        private static bool TryAnnotateMulThenShRdEaxEdxByCl(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 1 || idx >= instructions.Count)
                return false;

            // Pattern (e.g. loc_000880A4):
            //   mul <src>
            //   shrd eax, edx, cl
            // -> take a product and shift-right by variable amount (common fixed-point scaling).
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^shrd\s+eax\s*,\s*edx\s*,\s*cl\s*$", RegexOptions.IgnoreCase))
                return false;

            for (var back = 1; back <= 2 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^mul\s+.+$", RegexOptions.IgnoreCase))
                {
                    hint = "HINT: (eax*src) >> cl (mul + shrd)";
                    return true;
                }
            }

            return false;
        }

        private static bool TryAnnotatePackHiByteWithLow24(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 4 || idx >= instructions.Count)
                return false;

            // Pattern (e.g. loc_000880A4):
            //   mov eax, [base+offA]
            //   shl eax, 0x18
            //   mov edx, [base+offB]
            //   shr edx, 0x8
            //   or eax, edx
            // -> (byte<<24) | (low24bits)
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^or\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                return false;

            var i1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(i1, @"^shr\s+edx\s*,\s*(?:0x)?8\s*$", RegexOptions.IgnoreCase))
                return false;

            var i2 = instructions[idx - 2].ToString().Trim();
            var mMovEdx = Regex.Match(i2, @"^mov\s+edx\s*,\s*\[(?<base>e[a-z]{2})\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase);
            if (!mMovEdx.Success)
                return false;

            var i3 = instructions[idx - 3].ToString().Trim();
            if (!Regex.IsMatch(i3, @"^shl\s+eax\s*,\s*(?:0x)?18\s*$", RegexOptions.IgnoreCase))
                return false;

            var i4 = instructions[idx - 4].ToString().Trim();
            var mMovEax = Regex.Match(i4, @"^mov\s+eax\s*,\s*\[(?<base>e[a-z]{2})\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase);
            if (!mMovEax.Success)
                return false;

            // Require same base reg to reduce false positives.
            if (!mMovEax.Groups["base"].Value.Equals(mMovEdx.Groups["base"].Value, StringComparison.OrdinalIgnoreCase))
                return false;

            hint = "HINT: pack (byte<<24) | (val & 0x00FFFFFF)";
            return true;
        }

        private static bool TryAnnotatePackStride4BytesIntoDword(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 2 || idx + 3 >= instructions.Count)
                return false;

            // Pattern (e.g. loc_0008A163):
            //   mov ch, [eax+0xC]
            //   mov cl, [eax+0x8]
            //   shl ecx, 0x10
            //   mov ch, [eax+0x4]
            //   mov cl, [eax]
            //   mov [edx], ecx
            // -> pack 4 bytes from an interleaved/strided source into one dword.
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^shl\s+ecx\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase))
                return false;

            var iM2 = instructions[idx - 2].ToString().Trim();
            var iM1 = instructions[idx - 1].ToString().Trim();
            var iP1 = instructions[idx + 1].ToString().Trim();
            var iP2 = instructions[idx + 2].ToString().Trim();
            var iP3 = instructions[idx + 3].ToString().Trim();

            if (!Regex.IsMatch(iM2, @"^mov\s+ch\s*,\s*\[eax\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(iM1, @"^mov\s+cl\s*,\s*\[eax\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(iP1, @"^mov\s+ch\s*,\s*\[eax\+0x[0-9a-f]+\]\s*$", RegexOptions.IgnoreCase))
                return false;

            if (!Regex.IsMatch(iP2, @"^mov\s+cl\s*,\s*\[eax(?:\+0x[0-9a-f]+)?\]\s*$", RegexOptions.IgnoreCase))
                return false;

            if (!Regex.IsMatch(iP3, @"^mov\s+\[edx(?:\+0x[0-9a-f]+)?\]\s*,\s*ecx\s*$", RegexOptions.IgnoreCase))
                return false;

            hint = "HINT: pack 4 bytes (stride 4) into dword";
            return true;
        }

        private static bool TryAnnotateSar16BeforeImul(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            // Pattern: sar r32, 0x10 followed shortly by imul using that value.
            // Commonly used to convert fixed16.16 -> int before multiplication.
            var i0 = instructions[idx].ToString().Trim();
            var mSar = Regex.Match(i0, @"^sar\s+(?<reg>e[a-z]{2})\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase);
            if (!mSar.Success)
                return false;

            var reg = mSar.Groups["reg"].Value.ToLowerInvariant();

            // Look ahead for an imul that consumes reg.
            for (var j = idx + 1; j < instructions.Count && j <= idx + 3; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, $@"^imul\s+{Regex.Escape(reg)}\s*,\s*.+$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^imul\s+.+\s*,\s*{Regex.Escape(reg)}\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^imul\s+.+\s*,\s*\[.*{Regex.Escape(reg)}.*\]\s*$", RegexOptions.IgnoreCase))
                {
                    hint = "HINT: fixed16.16 -> int (>>16)";
                    return true;
                }

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            return false;
        }

        private static bool TryAnnotateMovEaxFromAbsScaled4(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            // Pattern: mov eax, [eax*4+0xF00D]
            // Interpretable as a 32-bit lookup table indexed by eax.
            var cur = instructions[idx].ToString().Trim();
            var m = Regex.Match(cur, @"^mov\s+eax\s*,\s*\[eax\*4\+(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var tok = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
            if (!TryParseHexOrDecUInt32(tok, out var abs))
                return false;

            hint = $"HINT: eax = table32[ eax ] @0x{abs:X}";
            return true;
        }

        private static bool TryAnnotateMulBy1000ViaShifts(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 5 || idx >= instructions.Count)
                return false;

            // Pattern (as seen in loc_0007D602):
            //   mov eax, edx
            //   shl eax, 0x5
            //   sub eax, edx          ; eax = edx*31
            //   shl eax, 0x2          ; eax = edx*124
            //   add edx, eax          ; edx = edx*125
            //   shl edx, 0x3          ; edx = edx*1000
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^(shl|sal)\s+edx\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return false;

            var i1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(i1, @"^add\s+edx\s*,\s*eax\s*$", RegexOptions.IgnoreCase))
                return false;

            var i2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(i2, @"^(shl|sal)\s+eax\s*,\s*(?:0x)?2\s*$", RegexOptions.IgnoreCase))
                return false;

            var i3 = instructions[idx - 3].ToString().Trim();
            if (!Regex.IsMatch(i3, @"^sub\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                return false;

            var i4 = instructions[idx - 4].ToString().Trim();
            if (!Regex.IsMatch(i4, @"^(shl|sal)\s+eax\s*,\s*(?:0x)?5\s*$", RegexOptions.IgnoreCase))
                return false;

            var i5 = instructions[idx - 5].ToString().Trim();
            if (!Regex.IsMatch(i5, @"^mov\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                return false;

            hint = "HINT: edx *= 1000 (x125<<3)";
            return true;
        }

        private static bool TryAnnotateSignedDivBy10DigitSplit(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 3 || idx >= instructions.Count)
                return false;

            // Common formatting idiom:
            //   mov esi, 0xa
            //   mov edx, <v>
            //   mov eax, <v>
            //   sar edx, 0x1f
            //   idiv esi
            // (repeat) -> quotient/remainder base-10
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^idiv\s+esi\s*$", RegexOptions.IgnoreCase))
                return false;

            var i1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(i1, @"^sar\s+edx\s*,\s*(?:0x)?1f\s*$", RegexOptions.IgnoreCase))
                return false;

            var i2 = instructions[idx - 2].ToString().Trim();
            var i3 = instructions[idx - 3].ToString().Trim();
            var mMovEax = Regex.Match(i2, @"^mov\s+eax\s*,\s*(?<src>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            var mMovEdx = Regex.Match(i3, @"^mov\s+edx\s*,\s*(?<src>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!mMovEax.Success || !mMovEdx.Success)
                return false;

            var srcA = mMovEax.Groups["src"].Value.ToLowerInvariant();
            var srcD = mMovEdx.Groups["src"].Value.ToLowerInvariant();
            if (!srcA.Equals(srcD, StringComparison.OrdinalIgnoreCase))
                return false;

            // Ensure divisor was set to 10 nearby.
            var foundTen = false;
            for (var back = 1; back <= 20 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^mov\s+esi\s*,\s*(?:0x)?0?a\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, @"^mov\s+esi\s*,\s*10\s*$", RegexOptions.IgnoreCase))
                {
                    foundTen = true;
                    break;
                }
            }
            if (!foundTen)
                return false;

            hint = "HINT: signed div by 10 (quot eax, rem edx)";
            return true;
        }

        private static bool TryAnnotateMovEsi10ForDigitExtract(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^mov\s+esi\s*,\s*(?:0x)?0?a\s*$", RegexOptions.IgnoreCase) &&
                !Regex.IsMatch(i0, @"^mov\s+esi\s*,\s*10\s*$", RegexOptions.IgnoreCase))
                return false;

            // Look ahead for the actual digit-split idiv pattern.
            var lookahead = 10;
            for (var j = idx + 1; j < instructions.Count && j <= idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^idiv\s+esi\s*$", RegexOptions.IgnoreCase))
                {
                    // Require sign-extend via sar edx, 0x1f nearby.
                    for (var back = 1; back <= 3 && j - back >= 0; back++)
                    {
                        var p = instructions[j - back].ToString().Trim();
                        if (Regex.IsMatch(p, @"^sar\s+edx\s*,\s*(?:0x)?1f\s*$", RegexOptions.IgnoreCase))
                        {
                            hint = "HINT: prepare for base-10 digit extraction (divisor=10)";
                            return true;
                        }
                    }
                }

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            return false;
        }

        private static bool TryAnnotateMulU8FromTwoMovzx(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 2 || idx >= instructions.Count)
                return false;

            // Pattern:
            //   movzx r1, byte [mem]
            //   movzx r2, byte [mem]
            //   imul r2, r1
            var i0 = instructions[idx].ToString().Trim();
            var mImul = Regex.Match(i0, @"^imul\s+(?<dst>e[a-z]{2})\s*,\s*(?<src>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!mImul.Success)
                return false;

            var dst = mImul.Groups["dst"].Value.ToLowerInvariant();
            var src = mImul.Groups["src"].Value.ToLowerInvariant();

            bool HasMovzxByteToReg(string t, string reg)
            {
                return Regex.IsMatch(
                    t,
                    $@"^movzx\s+{Regex.Escape(reg)}\s*,\s*byte\s+\[[^\]]+\]\s*$",
                    RegexOptions.IgnoreCase
                );
            }

            var p1 = instructions[idx - 1].ToString().Trim();
            var p2 = instructions[idx - 2].ToString().Trim();

            if ((HasMovzxByteToReg(p1, dst) && HasMovzxByteToReg(p2, src)) ||
                (HasMovzxByteToReg(p1, src) && HasMovzxByteToReg(p2, dst)))
            {
                hint = "HINT: u8*u8 multiply (size/scale)";
                return true;
            }

            return false;
        }

        private static bool TryAnnotateUnsignedDiv(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 1 || idx >= instructions.Count)
                return false;

            var i0 = instructions[idx].ToString().Trim();
            var m = Regex.Match(i0, @"^div\s+(?<div>e[a-d]x|e[sdi]i|e[bp]p|dword\s+\[[^\]]+\])\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var div = m.Groups["div"].Value.Trim();
            for (var back = 1; back <= 3 && idx - back >= 0; back++)
            {
                var p = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(p, @"^xor\s+edx\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                {
                    hint = $"HINT: unsigned div by {div} (eax=quot, edx=rem)";
                    return true;
                }

                if (Regex.IsMatch(p, @"^\s*(mov|lea|add|sub|xor|and|or|shl|shr|sar|imul)\s+edx\b", RegexOptions.IgnoreCase))
                    break;
            }

            return false;
        }

        private static bool TryAnnotateShift16Add8000FlatPtr(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 1 || idx >= instructions.Count)
                return false;

            // Common DOS4GW LE idiom:
            //   shl reg, 0x10
            //   add reg, 0x8000
            // Interpretable as building a flat pointer from a 16:16-ish value.
            var cur = instructions[idx].ToString().Trim();
            var mAdd = Regex.Match(cur, @"^add\s+(?<reg>e[a-z]{2})\s*,\s*(?:0x)?8000\s*$", RegexOptions.IgnoreCase);
            if (!mAdd.Success)
                return false;

            var reg = mAdd.Groups["reg"].Value.ToLowerInvariant();

            var prev = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(prev, $@"^(shl|sal)\s+{Regex.Escape(reg)}\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase))
                return false;

            hint = $"HINT: build flat ptr: ({reg}<<16)+0x8000";
            return true;
        }

        private static bool TryAnnotateImulImplicitEax64(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            // One-operand IMUL form (implicit EAX):
            //   imul r/m32
            // Semantics: EDX:EAX = EAX * r/m32 (signed 64-bit result)
            var cur = instructions[idx].ToString().Trim();
            var m = Regex.Match(cur, @"^imul\s+(?<op>(?:dword\s+)?\[[^\]]+\]|e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var op = m.Groups["op"].Value.Trim();
            hint = $"HINT: edx:eax = eax * {op} (signed 64-bit)";
            return true;
        }

        private static bool TryAnnotateFixedPointDivShift16(List<Instruction> instructions, int idx, out string hint)
        {
            hint = null;
            if (instructions == null || idx < 3 || idx >= instructions.Count)
                return false;

            // Pattern:
            //   shl edx, 0x10
            //   mov eax, edx
            //   sar edx, 0x1f
            //   idiv ecx
            // Semantics: EAX ~= (value<<16) / ECX (signed), common 16.16 fixed-point ratio.
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^idiv\s+ecx\s*$", RegexOptions.IgnoreCase))
                return false;

            var i1 = instructions[idx - 1].ToString().Trim();
            var i2 = instructions[idx - 2].ToString().Trim();
            var i3 = instructions[idx - 3].ToString().Trim();

            if (!Regex.IsMatch(i1, @"^sar\s+edx\s*,\s*(?:0x)?1f\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i2, @"^mov\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
                return false;
            if (!Regex.IsMatch(i3, @"^(shl|sal)\s+edx\s*,\s*(?:0x)?10\s*$", RegexOptions.IgnoreCase))
                return false;

            hint = "HINT: fixed-point div: eax = (value<<16)/ecx (16.16); edx=rem";
            return true;
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

            static bool IsLikelyEaxMemNoise(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim().ToLowerInvariant();

                // Common "all zeros" / low-entropy patterns when decoding data as code.
                if (s == "add [eax], al" || s == "add [eax], eax")
                    return true;
                if (s == "or [eax], al" || s == "and [eax], al" || s == "sub [eax], al" || s == "adc [eax], al" || s == "sbb [eax], al")
                    return true;
                if (s == "or [eax], cl" || s == "and [eax], cl" || s == "adc [eax], cl" || s == "sbb [eax], cl")
                    return true;

                // Generalize a bit (still quite strict): ops on [eax] with a byte reg.
                if (Regex.IsMatch(s, @"^(add|or|and|sub|adc|sbb|cmp|test|xor)\s+\[eax\],\s*(al|cl|dl|bl|ah|ch|dh|bh)\s*$", RegexOptions.IgnoreCase))
                    return true;

                return false;
            }

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
            var noise = 0;
            var weird = 0;

            for (var i = lo; i <= hi; i++)
            {
                var t = instructions[i].ToString();
                if (IsLikelyEaxMemNoise(t)) noise++;
                if (IsWeirdPrivOrSeg(t)) weird++;
            }

            // Trigger if we see a lot of low-entropy [eax],reg8 noise, or lots of privileged/segment-ish ops.
            // This catches common data regions that disassemble into "add/or/and [eax], xx" plus rare ops.
            if (!(noise >= 8 || (noise >= 5 && weird >= 2) || weird >= 6))
                return string.Empty;

            var cur = instructions[idx].ToString();
            if (IsLikelyEaxMemNoise(cur))
                return "NOTE: suspicious decode (low-entropy [eax] ops) — likely data, not code";

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

                    // Also common: mov eax, edx; sar edx, 0x1f; idiv <div>
                    if (Regex.IsMatch(p, @"^\s*mov\s+eax\s*,\s*edx\s*$", RegexOptions.IgnoreCase))
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
