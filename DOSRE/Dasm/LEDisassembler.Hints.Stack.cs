using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static bool TryParseSubEspImm(string insText, out uint imm)
        {
            imm = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples: sub esp, 0x34 | sub esp, 0x120
            var m = Regex.Match(insText.Trim(), @"^sub\s+esp\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var tok = m.Groups["imm"].Value.Trim();
            tok = tok.TrimEnd('h', 'H');
            return TryParseHexOrDecUInt32(tok, out imm);
        }

        private static string TryAnnotateStackAlloc(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx <= 0 || idx >= instructions.Count)
                return string.Empty;

            var cur = instructions[idx].ToString();
            if (!TryParseSubEspImm(cur, out var imm))
                return string.Empty;

            // Only annotate "large" allocations to reduce noise.
            if (imm < 0x20)
                return string.Empty;

            var prev = instructions[idx - 1].ToString().Trim();
            if (!prev.Equals("push ebp", StringComparison.OrdinalIgnoreCase) && !prev.Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            return $"HINT: stack alloc 0x{imm:X} (locals/arg block)";
        }

        private static string TryAnnotateScale8TableLoad(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern (common in big uncommented setup blocks):
            //   mov eax, [base+idx*8]       ; lo dword of an 8-byte entry
            //   mov eax, [base+idx*8+0x4]   ; hi dword
            // Often interleaved with stores/reloads, so annotate each load.
            var a = instructions[idx].ToString().Trim();
            var m = Regex.Match(a, @"^mov\s+eax\s*,\s*\[(?<base>e[a-z]{2})\+(?<idx>e[a-z]{2})\*8(?<off>\+0x(?<disp>[0-9A-Fa-f]+))?\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return string.Empty;

            var baseReg = m.Groups["base"].Value.ToLowerInvariant();
            var idxReg = m.Groups["idx"].Value.ToLowerInvariant();

            uint disp = 0;
            var dispGroup = m.Groups["disp"].Value;
            if (!string.IsNullOrEmpty(dispGroup))
            {
                if (!TryParseHexOrDecUInt32(dispGroup, out disp))
                    disp = 0;
            }

            var which = disp == 4 ? "hi" : "lo";
            return $"HINT: load {which} dword of 8-byte entry: [{baseReg}+{idxReg}*8{(disp != 0 ? $"+0x{disp:X}" : string.Empty)}]";
        }

        private static string TryAnnotateUnalignedU16LoadViaShr(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 4 || idx >= instructions.Count)
                return string.Empty;

            // Pattern (seen in loc_0007CEB6):
            //   lea eax, [esi+disp]
            //   mov eax, [ecx+eax-0x4]    ; with ecx=2
            //   neg ecx
            //   lea ecx, [ecx*8+0x20]     ; yields cl=0x10
            //   shr eax, cl               ; -> extracts u16 at [esi+disp]
            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^shr\s+eax\s*,\s*cl\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var p1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(p1, @"^lea\s+ecx\s*,\s*\[ecx\*8\+0x20\]\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var p2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(p2, @"^neg\s+ecx\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            // Find the `mov eax, [ecx+eax-0x4]` within a small window.
            var movIdx = -1;
            for (var back = 3; back <= 6; back++)
            {
                if (idx - back < 0)
                    break;
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^mov\s+eax\s*,\s*\[ecx\+eax-0x4\]\s*$", RegexOptions.IgnoreCase))
                {
                    movIdx = idx - back;
                    break;
                }
            }
            if (movIdx < 0)
                return string.Empty;

            // Find the `lea eax, [base+disp]` shortly before that mov.
            Match mLea = null;
            for (var back = 1; back <= 3; back++)
            {
                var leaPos = movIdx - back;
                if (leaPos < 0)
                    break;
                var t = instructions[leaPos].ToString().Trim();
                var m = Regex.Match(t, @"^lea\s+eax\s*,\s*\[(?<base>e[a-z]{2})\+(?:0x)?(?<disp>[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    mLea = m;
                    break;
                }
            }
            if (mLea == null)
                return string.Empty;

            var baseReg = mLea.Groups["base"].Value.ToLowerInvariant();
            if (!TryParseHexOrDecUInt32(mLea.Groups["disp"].Value, out var disp))
                return string.Empty;

            // This idiom specifically shifts by 16 (cl=0x10), extracting the word at the original address.
            return $"HINT: eax = u16([{baseReg}+0x{disp:X}]) (unaligned via dword>>16)";
        }

        private static string TryAnnotateIncAndMod4(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 2 || idx >= instructions.Count)
                return string.Empty;

            // Pattern:
            //   mov reg, [esp+0x....]
            //   inc reg
            //   and reg, 0x3
            // Common for ring buffer index mod 4.
            var cur = instructions[idx].ToString().Trim();
            var mAnd = Regex.Match(cur, @"^and\s+(?<r>e[a-z]{2})\s*,\s*0x3\s*$", RegexOptions.IgnoreCase);
            if (!mAnd.Success)
                return string.Empty;

            var r = mAnd.Groups["r"].Value.ToLowerInvariant();
            var prev = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(prev, $@"^inc\s+{Regex.Escape(r)}\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var prev2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(prev2, $@"^mov\s+{Regex.Escape(r)}\s*,\s*\[esp\+0x[0-9A-Fa-f]+\]\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            return "HINT: idx = (idx+1) & 3 (mod 4)";
        }

        private static string TryAnnotateScale8PtrAdd(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 1 || idx >= instructions.Count)
                return string.Empty;

            // Pattern:
            //   shl reg, 0x3
            //   add reg, base
            // where base is typically loaded from [esp+0x4880] (points array base).
            var cur = instructions[idx].ToString().Trim();
            var mAdd = Regex.Match(cur, @"^add\s+(?<dst>e[a-z]{2})\s*,\s*(?<base>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!mAdd.Success)
                return string.Empty;

            var dst = mAdd.Groups["dst"].Value.ToLowerInvariant();
            var prev = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(prev, $@"^(shl|sal)\s+{Regex.Escape(dst)}\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            return $"HINT: ptr = base + {dst}*8 (8-byte entries)";
        }
    }
}
