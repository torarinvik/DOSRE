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

        private static string TryAnnotateZeroInitStackLocals(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            static bool IsMovEspStore(string t, out string srcReg, out string disp)
            {
                srcReg = string.Empty;
                disp = string.Empty;
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim();
                var m = Regex.Match(
                    s,
                    @"^mov\s+\[esp(?<disp>\+0x[0-9A-Fa-f]+)?\]\s*,\s*(?<r>e[a-z]{2})\s*$",
                    RegexOptions.IgnoreCase
                );
                if (!m.Success)
                    return false;

                srcReg = m.Groups["r"].Value.ToLowerInvariant();
                disp = m.Groups["disp"].Value;
                return true;
            }

            if (!IsMovEspStore(instructions[idx].ToString(), out var r0, out _))
                return string.Empty;

            // Require a recent zeroing of the source reg.
            var zeroed = false;
            for (var back = 1; back <= 4 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (Regex.IsMatch(t, $@"^(?:xor|sub)\s+{Regex.Escape(r0)}\s*,\s*{Regex.Escape(r0)}\s*$", RegexOptions.IgnoreCase)
                    || Regex.IsMatch(t, $@"^mov\s+{Regex.Escape(r0)}\s*,\s*(?:0x0+|0)\s*$", RegexOptions.IgnoreCase))
                {
                    zeroed = true;
                    break;
                }
            }
            if (!zeroed)
                return string.Empty;

            // Annotate only at the first store in this local streak.
            for (var back = 1; back <= 6 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsMovEspStore(t, out var r, out _)
                    && r.Equals(r0, StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty;
                }
            }

            var lookahead = 10;
            var stores = 0;
            var uniqueOffsets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsMovEspStore(t, out var r, out var disp)
                    && r.Equals(r0, StringComparison.OrdinalIgnoreCase))
                {
                    stores++;
                    uniqueOffsets.Add(string.IsNullOrEmpty(disp) ? "+0x0" : disp);
                }
            }

            if (stores < 4 || uniqueOffsets.Count < 3)
                return string.Empty;

            return "HINT: zero-init stack locals/arg block";
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

        private static string TryAnnotateScale8EntryLoadViaLeaAdd(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 2 || idx + 1 >= instructions.Count)
                return string.Empty;

            // Pattern (seen in loc_000770B3 / loc_00077B63):
            //   lea tmp, [idx*8]
            //   add tmp, base
            //   mov hi, [tmp+0x4]
            //   mov lo, [tmp]
            // -> load 8-byte entry via computed address.
            var cur = instructions[idx].ToString().Trim();
            var mHi = Regex.Match(cur, @"^mov\s+(?<hi>e[a-z]{2})\s*,\s*\[(?<tmp>e[a-z]{2})\+0x4\]\s*$", RegexOptions.IgnoreCase);
            if (!mHi.Success)
                return string.Empty;

            var tmp = mHi.Groups["tmp"].Value.ToLowerInvariant();

            var next = instructions[idx + 1].ToString().Trim();
            if (!Regex.IsMatch(next, $@"^mov\s+e[a-z]{{2}}\s*,\s*\[{Regex.Escape(tmp)}\]\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var prev = instructions[idx - 1].ToString().Trim();
            var mAdd = Regex.Match(prev, $@"^add\s+{Regex.Escape(tmp)}\s*,\s*(?<base>e[a-z]{{2}})\s*$", RegexOptions.IgnoreCase);
            if (!mAdd.Success)
                return string.Empty;

            var baseReg = mAdd.Groups["base"].Value.ToLowerInvariant();
            var prev2 = instructions[idx - 2].ToString().Trim();
            var mLea = Regex.Match(prev2, $@"^lea\s+{Regex.Escape(tmp)}\s*,\s*\[(?<idx>e[a-z]{{2}})\*8\]\s*$", RegexOptions.IgnoreCase);
            if (!mLea.Success)
                return string.Empty;

            var idxReg = mLea.Groups["idx"].Value.ToLowerInvariant();
            return $"HINT: load 8-byte entry via [{baseReg}+{idxReg}*8]";
        }

        private static string TryAnnotateStructInitInterleavedAtEax(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Heuristic: within a short window, many constant stores to [eax+disp] (even if interleaved with LEA/MOV)
            // usually mean struct/object init.
            static bool IsConstStoreToEax(string t, out string disp)
            {
                disp = string.Empty;
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim();
                var m = Regex.Match(
                    s,
                    @"^mov\s+(?:byte|word|dword)\s+\[eax(?<disp>\+0x[0-9A-Fa-f]+)?\]\s*,\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$",
                    RegexOptions.IgnoreCase
                );
                if (!m.Success)
                    return false;

                disp = m.Groups["disp"].Value;
                return true;
            }

            if (!IsConstStoreToEax(instructions[idx].ToString(), out _))
                return string.Empty;

            // Only annotate at the first const-store in the local init window.
            for (var back = 1; back <= 6 && idx - back >= 0; back++)
            {
                if (IsConstStoreToEax(instructions[idx - back].ToString(), out _))
                    return string.Empty;

                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            var lookahead = 18;
            var constStores = 0;
            var uniqueOffsets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsConstStoreToEax(t, out var disp))
                {
                    constStores++;
                    uniqueOffsets.Add(string.IsNullOrEmpty(disp) ? "+0x0" : disp);
                }
            }

            // Keep noise low: require a fairly dense init.
            if (constStores < 6 || uniqueOffsets.Count < 5)
                return string.Empty;

            return "HINT: init struct @eax (defaults/fields)";
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

        private static string TryAnnotateMovsdBlockCopy(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern (e.g. func_00076C42):
            //   lea edi, [dst]
            //   lea esi, [src]
            //   movsd
            //   movsd
            // -> copy 8 bytes (2 dwords) from src to dst.
            var cur = instructions[idx].ToString().Trim();
            if (!cur.Equals("movsd", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Only annotate the first movsd in a pair to reduce noise.
            if (idx > 0 && instructions[idx - 1].ToString().Trim().Equals("movsd", StringComparison.OrdinalIgnoreCase))
                return string.Empty;
            if (idx + 1 >= instructions.Count || !instructions[idx + 1].ToString().Trim().Equals("movsd", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Require nearby lea edi/esi setup.
            var sawLeaEdi = false;
            var sawLeaEsi = false;
            for (var back = 1; back <= 4 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (!sawLeaEdi && Regex.IsMatch(t, @"^lea\s+edi\s*,\s*\[.+\]\s*$", RegexOptions.IgnoreCase))
                    sawLeaEdi = true;
                if (!sawLeaEsi && Regex.IsMatch(t, @"^lea\s+esi\s*,\s*\[.+\]\s*$", RegexOptions.IgnoreCase))
                    sawLeaEsi = true;

                if (sawLeaEdi && sawLeaEsi)
                    break;
            }

            if (!sawLeaEdi || !sawLeaEsi)
                return string.Empty;

            return "HINT: memcpy 8 bytes (2 dwords) via movsd";
        }

        private static string TryAnnotateStructInitDefaultsAtEax(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Heuristic: a dense run of constant stores to [eax+disp] is typically struct init / defaults.
            // Example block: mov dword [eax],0; mov byte [eax+0x17],0xff; mov dword [eax+0x4],0xffffffff; ...
            static bool IsConstStoreToEax(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;
                var s = t.Trim();
                return Regex.IsMatch(
                    s,
                    @"^mov\s+(?:byte|word|dword)\s+\[eax(?:\+0x[0-9A-Fa-f]+)?\]\s*,\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$",
                    RegexOptions.IgnoreCase
                );
            }

            var cur = instructions[idx].ToString();
            if (!IsConstStoreToEax(cur))
                return string.Empty;

            // Identify the bounds of the contiguous const-store streak.
            var start = idx;
            while (start > 0 && IsConstStoreToEax(instructions[start - 1].ToString()))
                start--;

            var end = idx;
            while (end + 1 < instructions.Count && IsConstStoreToEax(instructions[end + 1].ToString()))
                end++;

            var count = end - start + 1;
            if (count < 8)
                return string.Empty;

            var pos = idx - start;

            // Keep noise low: annotate at the start, and once more mid-streak for longer init runs.
            if (pos == 0)
                return $"HINT: init struct @eax (set {count} default fields)";
            if (count >= 10 && pos == 5)
                return "HINT: init struct @eax (continued)";

            return string.Empty;
        }

        private static string TryAnnotatePushArgsBeforeIndirectCall(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Heuristic: a run of pushes shortly followed by an indirect call often means
            // the block is preparing stack args for a callback/dispatch.
            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^push\s+.+$", RegexOptions.IgnoreCase))
                return string.Empty;

            var lookahead = 16;
            var pushes = 0;
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^push\s+.+$", RegexOptions.IgnoreCase))
                    pushes++;

                if (Regex.IsMatch(t, @"^call\s+(?:dword\s+)?\[(?:esp|ebp)\+0x[0-9A-Fa-f]+\]\s*$", RegexOptions.IgnoreCase))
                {
                    if (pushes >= 3)
                        return "HINT: build stack args for indirect call";
                    return string.Empty;
                }

                // Also catch direct calls with a lot of pushes (often a large argument pack).
                if (Regex.IsMatch(t, @"^call\s+(?:0x[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]*)(?:\s+;.*)?$", RegexOptions.IgnoreCase))
                {
                    if (pushes >= 5)
                        return "HINT: build stack args for call";
                    return string.Empty;
                }

                // Stop scanning if we hit another control-transfer; we only want local setup.
                if (j != idx && Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    return string.Empty;
            }

            return string.Empty;
        }

        private static string TryAnnotateRepStosbMemset(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^rep\s+stosb\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            // Look back for: mov ecx, <count> and xor eax, eax (zero-fill) and maybe mov edi, <dst>.
            string countText = "ecx";
            var isZeroFill = false;
            for (var back = 1; back <= 6 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();

                var mCount = Regex.Match(t, @"^mov\s+ecx\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
                if (mCount.Success)
                    countText = mCount.Groups["imm"].Value;

                if (Regex.IsMatch(t, @"^xor\s+eax\s*,\s*eax\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, @"^xor\s+al\s*,\s*al\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, @"^mov\s+al\s*,\s*0x0+\s*$", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, @"^mov\s+al\s*,\s*0\s*$", RegexOptions.IgnoreCase))
                {
                    isZeroFill = true;
                }

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            if (!isZeroFill)
                return "HINT: memset(dst=edi, value=al, count=ecx)";

            return $"HINT: memset(dst=edi, 0, count={countText})";
        }

        private static string TryAnnotateRepMovsdMemcpy(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^rep\s+movsd\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            // Look back for: mov ecx, <count>
            string countText = "ecx";
            for (var back = 1; back <= 6 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                var mCount = Regex.Match(t, @"^mov\s+ecx\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
                if (mCount.Success)
                {
                    countText = mCount.Groups["imm"].Value;
                    break;
                }

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            return $"HINT: memcpy(dst=edi, src=esi, dwords={countText}) via rep movsd";
        }

        private static string TryAnnotateMemcpyBytesViaRepMovs(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 2 || idx + 3 >= instructions.Count)
                return string.Empty;

            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^(?:rep|repne)\s+movsd\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var p1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(p1, @"^shr\s+ecx\s*,\s*(?:0x)?2\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var p2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(p2, @"^mov\s+eax\s*,\s*ecx\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var n1 = instructions[idx + 1].ToString().Trim();
            var n2 = instructions[idx + 2].ToString().Trim();
            var n3 = instructions[idx + 3].ToString().Trim();
            if (!Regex.IsMatch(n1, @"^mov\s+cl\s*,\s*al\s*$", RegexOptions.IgnoreCase))
                return string.Empty;
            if (!Regex.IsMatch(n2, @"^and\s+cl\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return string.Empty;
            if (!Regex.IsMatch(n3, @"^(?:rep|repne)\s+movsb\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            return "HINT: memcpy bytes via rep movsd + tail movsb (count in eax)";
        }

        private static string TryAnnotateStructStoreStreakAtEax(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            static bool IsStoreToEax(string t, out string disp)
            {
                disp = string.Empty;
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim();
                var m = Regex.Match(
                    s,
                    @"^mov\s+(?:byte|word|dword\s+)?\[eax(?<disp>\+0x[0-9A-Fa-f]+)?\]\s*,\s*.+$",
                    RegexOptions.IgnoreCase
                );
                if (!m.Success)
                    return false;

                disp = m.Groups["disp"].Value;
                return true;
            }

            if (!IsStoreToEax(instructions[idx].ToString(), out _))
                return string.Empty;

            // Annotate at the first store in the local streak.
            for (var back = 1; back <= 5 && idx - back >= 0; back++)
            {
                if (IsStoreToEax(instructions[idx - back].ToString(), out _))
                    return string.Empty;

                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            var lookahead = 18;
            var stores = 0;
            var uniqueOffsets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsStoreToEax(t, out var disp))
                {
                    stores++;
                    uniqueOffsets.Add(string.IsNullOrEmpty(disp) ? "+0x0" : disp);
                }
            }

            // Keep noise low: only for dense init/update blocks.
            if (stores < 8 || uniqueOffsets.Count < 6)
                return string.Empty;

            return "HINT: init/update struct @eax (many field stores)";
        }

        private static string TryAnnotateGlobalPtrFieldStoreStreak(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            static bool IsStoreToPtrField(string t, out string baseSym, out string field)
            {
                baseSym = string.Empty;
                field = string.Empty;
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim();
                var m = Regex.Match(
                    s,
                    @"^mov\s+(?:(?:byte|word|dword)\s+)?\[(?<base>ptr_[0-9A-Fa-f]{8})\.(?<field>field_[0-9A-Fa-f]+)\]\s*,\s*.+$",
                    RegexOptions.IgnoreCase
                );
                if (!m.Success)
                    return false;

                baseSym = m.Groups["base"].Value;
                field = m.Groups["field"].Value;
                return true;
            }

            if (!IsStoreToPtrField(instructions[idx].ToString(), out var baseSym0, out _))
                return string.Empty;

            // Annotate at the first store in the local streak for this base symbol.
            for (var back = 1; back <= 8 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsStoreToPtrField(t, out var baseSym, out _)
                    && baseSym.Equals(baseSym0, StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty;
                }
            }

            var lookahead = 22;
            var stores = 0;
            var uniqueFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsStoreToPtrField(t, out var baseSym, out var field)
                    && baseSym.Equals(baseSym0, StringComparison.OrdinalIgnoreCase))
                {
                    stores++;
                    uniqueFields.Add(field);
                }
            }

            // Keep noise low: only for dense init/update blocks.
            if (stores < 7 || uniqueFields.Count < 6)
                return string.Empty;

            return $"HINT: init/update global struct @{baseSym0} (many field stores)";
        }

        private static string TryAnnotateStructInitDefaultsAtLoadedPtrReg(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            static bool IsConstStoreToReg(string t, out string reg, out string disp)
            {
                reg = string.Empty;
                disp = string.Empty;
                if (string.IsNullOrWhiteSpace(t))
                    return false;

                var s = t.Trim();
                var m = Regex.Match(
                    s,
                    @"^mov\s+(?:byte|word|dword)\s+(?:ptr\s+)?\[(?<reg>e[a-z]{2})(?<disp>\+0x[0-9A-Fa-f]+)?\]\s*,\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$",
                    RegexOptions.IgnoreCase
                );
                if (!m.Success)
                    return false;

                reg = m.Groups["reg"].Value.ToLowerInvariant();
                disp = m.Groups["disp"].Value;
                return true;
            }

            if (!IsConstStoreToReg(instructions[idx].ToString(), out var baseReg, out _))
                return string.Empty;

            // Don't fight the existing @eax heuristics.
            if (baseReg.Equals("eax", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Keep noise low: only when the base reg was just loaded from an absolute/global pointer.
            var loadedFromAbs = false;
            for (var back = 1; back <= 4 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (Regex.IsMatch(
                        t,
                        $@"^mov\s+{Regex.Escape(baseReg)}\s*,\s*(?:dword\s+)?\[(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*$",
                        RegexOptions.IgnoreCase
                    )
                    || Regex.IsMatch(
                        t,
                        $@"^mov\s+{Regex.Escape(baseReg)}\s*,\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\s*$",
                        RegexOptions.IgnoreCase
                    ))
                {
                    loadedFromAbs = true;
                    break;
                }
            }
            if (!loadedFromAbs)
                return string.Empty;

            // Annotate at the first const-store in the local init window.
            for (var back = 1; back <= 8 && idx - back >= 0; back++)
            {
                var t = instructions[idx - back].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsConstStoreToReg(t, out var r, out _)
                    && r.Equals(baseReg, StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty;
                }
            }

            var lookahead = 20;
            var constStores = 0;
            var uniqueOffsets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var j = idx; j < instructions.Count && j < idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (IsConstStoreToReg(t, out var r, out var disp))
                {
                    if (!r.Equals(baseReg, StringComparison.OrdinalIgnoreCase))
                        continue;

                    constStores++;
                    uniqueOffsets.Add(string.IsNullOrEmpty(disp) ? "+0x0" : disp);
                }
            }

            if (constStores < 6 || uniqueOffsets.Count < 5)
                return string.Empty;

            return $"HINT: init struct @{baseReg} (defaults/fields)";
        }

        private static string TryAnnotateComputeRemainingIndexIn4(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 2 || idx >= instructions.Count)
                return string.Empty;

            // Pattern (seen in loc_000770B3 / loc_00077B63):
            //   mov edx, 0x3
            //   or  eax, esi
            //   sub edx, eax
            var i0 = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(i0, @"^sub\s+edx\s*,\s*eax\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var i1 = instructions[idx - 1].ToString().Trim();
            if (!Regex.IsMatch(i1, @"^or\s+eax\s*,\s*esi\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            var i2 = instructions[idx - 2].ToString().Trim();
            if (!Regex.IsMatch(i2, @"^mov\s+edx\s*,\s*(?:0x)?3\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            return "HINT: compute remaining index in 0..3 (edx = 3 - (a|b))";
        }

        private static string TryAnnotateStructFieldStoreDlAtEaxAfterDefaults(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern: mov [eax+disp], dl following a dense defaults init streak to eax.
            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^mov\s+\[eax\+0x[0-9A-Fa-f]+\]\s*,\s*dl\s*$", RegexOptions.IgnoreCase))
                return string.Empty;

            // If we recently wrote lots of constants to [eax+disp], interpret this as
            // finishing init with a couple fields copied from inputs.
            var lookback = 20;
            var constStores = 0;
            for (var j = idx - 1; j >= 0 && j >= idx - lookback; j--)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^mov\s+(?:byte|word|dword)\s+\[eax(?:\+0x[0-9A-Fa-f]+)?\]\s*,\s*(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase))
                    constStores++;

                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            if (constStores < 6)
                return string.Empty;

            return "HINT: struct init: copy byte field(s) from dl";
        }

        private static string TryAnnotateAbsStoreStreak(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            // Pattern: mov [0xADDR], <src> (optionally with size: mov dword [0xADDR], <src>)
            var cur = instructions[idx].ToString().Trim();
            if (!Regex.IsMatch(cur, @"^mov\s+(?:byte|word|dword\s+)?\[(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*.+$", RegexOptions.IgnoreCase))
                return string.Empty;

            // Only annotate when there are several absolute stores clustered together.
            var lookahead = 14;
            var ahead = 0;
            for (var j = idx; j < instructions.Count && j <= idx + lookahead; j++)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^mov\s+(?:byte|word|dword\s+)?\[(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*.+$", RegexOptions.IgnoreCase))
                    ahead++;

                if (j != idx && Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;
            }

            if (ahead < 3)
                return string.Empty;

            var lookback = 14;
            var behind = 0;
            for (var j = idx - 1; j >= 0 && j >= idx - lookback; j--)
            {
                var t = instructions[j].ToString().Trim();
                if (Regex.IsMatch(t, @"^(?:call|jmp|ret)\b", RegexOptions.IgnoreCase))
                    break;

                if (Regex.IsMatch(t, @"^mov\s+(?:byte|word|dword\s+)?\[(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*.+$", RegexOptions.IgnoreCase))
                    behind++;
            }

            if (behind == 0)
                return "HINT: update globals/state";
            if (behind == 2)
                return "HINT: update globals/state (continued)";
            if (behind == 3)
                return "HINT: update globals/state (continued)";

            return string.Empty;
        }
    }
}
