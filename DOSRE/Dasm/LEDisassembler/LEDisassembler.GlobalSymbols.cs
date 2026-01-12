using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static bool IsRegister32(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;
            switch (token.Trim().ToLowerInvariant())
            {
                case "eax":
                case "ebx":
                case "ecx":
                case "edx":
                case "esi":
                case "edi":
                case "ebp":
                case "esp":
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryParseImm32(string token, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(token))
                return false;

            var t = token.Trim();
            var m = Regex.Match(t, @"^0x(?<hex>[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            value = Convert.ToUInt32(m.Groups["hex"].Value, 16);
            return true;
        }

        private static bool TryResolveRegisterValueBefore(List<Instruction> instructions, int indexExclusive, string reg, out uint value, HashSet<uint> resourceGetterTargets = null)
        {
            value = 0;
            if (instructions == null || indexExclusive <= 0)
                return false;
            if (!IsRegister32(reg))
                return false;

            var start = Math.Min(indexExclusive - 1, instructions.Count - 1);
            var stop = Math.Max(0, start - 64);

            // Small forward constant-tracker across a short window.
            // This is intentionally conservative: it only tracks immediate constants and simple arithmetic.
            var known = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var vals = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in new[] { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" })
                known[r] = false;

            for (var i = stop; i <= start; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                // Resource getter: best-effort propagate eax = base + id across detected helper calls.
                // We intentionally do not require that edx was tracked as a constant: instead we re-scan the
                // immediate window before the call for the typical (base,id) setup pattern.
                if (resourceGetterTargets != null && resourceGetterTargets.Count > 0)
                {
                    var mcall = Regex.Match(t, @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (mcall.Success && TryParseHexUInt(mcall.Groups["target"].Value, out var tgt) && resourceGetterTargets.Contains(tgt))
                    {
                        if (TryComputeResourceGetterReturn(instructions, i, out var derived))
                        {
                            known["eax"] = true;
                            vals["eax"] = derived;
                        }
                        continue;
                    }
                }

                // xor r, r => 0
                var mxor = Regex.Match(t, @"^xor\s+(?<r>e[a-z]{2}),\s*\k<r>$", RegexOptions.IgnoreCase);
                if (mxor.Success)
                {
                    var r0 = mxor.Groups["r"].Value.ToLowerInvariant();
                    known[r0] = true;
                    vals[r0] = 0;
                    continue;
                }

                // mov r, 0x...
                var mmovImm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (mmovImm.Success)
                {
                    var dst = mmovImm.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(mmovImm.Groups["imm"].Value, out var imm))
                    {
                        known[dst] = true;
                        vals[dst] = imm;
                    }
                    continue;
                }

                // mov r, r
                var mmovReg = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<src>e[a-z]{2})$", RegexOptions.IgnoreCase);
                if (mmovReg.Success)
                {
                    var dst = mmovReg.Groups["dst"].Value.ToLowerInvariant();
                    var src = mmovReg.Groups["src"].Value.ToLowerInvariant();
                    if (known.TryGetValue(src, out var srcKnown) && srcKnown && vals.TryGetValue(src, out var srcVal))
                    {
                        known[dst] = true;
                        vals[dst] = srcVal;
                    }
                    else
                    {
                        known[dst] = false;
                    }
                    continue;
                }

                // add r, 0x...
                var madd = Regex.Match(t, @"^add\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (madd.Success)
                {
                    var dst = madd.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(madd.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = unchecked(cur + imm);
                    }
                    continue;
                }

                // sub r, 0x...
                var msub = Regex.Match(t, @"^sub\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (msub.Success)
                {
                    var dst = msub.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(msub.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = unchecked(cur - imm);
                    }
                    continue;
                }

                // lea r, [base+0xdisp] or lea r, [base+disp]
                var mlea = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (mlea.Success)
                {
                    var dst = mlea.Groups["dst"].Value.ToLowerInvariant();
                    var bas = mlea.Groups["base"].Value.ToLowerInvariant();
                    var disp = Convert.ToUInt32(mlea.Groups["disp"].Value, 16);
                    if (known.TryGetValue(bas, out var baseKnown) && baseKnown && vals.TryGetValue(bas, out var baseVal))
                    {
                        known[dst] = true;
                        vals[dst] = unchecked(baseVal + disp);
                    }
                    else
                    {
                        known[dst] = false;
                    }
                    continue;
                }
            }

            var rr = reg.Trim().ToLowerInvariant();
            if (known.TryGetValue(rr, out var k) && k && vals.TryGetValue(rr, out var v))
            {
                value = v;
                return true;
            }

            return false;
        }

        private static bool TryComputeResourceGetterReturn(List<Instruction> instructions, int callIdx, out uint value)
        {
            value = 0;
            if (instructions == null || callIdx <= 0 || callIdx >= instructions.Count)
                return false;

            uint? offsetImm = null;
            uint? regionBase = null;

            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 12; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                // Stop at control-flow barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // id: mov eax, 0xNNNN (small)
                var mo = Regex.Match(t, @"^mov\s+eax,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (offsetImm == null && mo.Success && TryParseImm32(mo.Groups["imm"].Value, out var oi) && oi < 0x10000)
                {
                    offsetImm = oi;
                    continue;
                }

                // base: add edx, 0xE0000 (or similar)
                var ma = Regex.Match(t, @"^add\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && ma.Success && TryParseImm32(ma.Groups["imm"].Value, out var rb) && rb >= 0x10000)
                {
                    regionBase = rb;
                    continue;
                }

                // base: mov edx, 0xE0000
                var mm = Regex.Match(t, @"^mov\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && mm.Success && TryParseImm32(mm.Groups["imm"].Value, out var rb2) && rb2 >= 0x10000)
                {
                    regionBase = rb2;
                    continue;
                }

                // base: lea edx, [<reg>+0xE0000]
                var ml = Regex.Match(t, @"^lea\s+edx,\s*\[e[a-z]{2}\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (regionBase == null && ml.Success)
                {
                    var disp = Convert.ToUInt32(ml.Groups["disp"].Value, 16);
                    if (disp >= 0x10000)
                        regionBase = disp;
                    continue;
                }

                if (offsetImm.HasValue && regionBase.HasValue)
                    break;
            }

            if (!offsetImm.HasValue || !regionBase.HasValue)
                return false;

            // Keep it conservative: common DOS4GW resource region patterns
            var rbv = regionBase.Value;
            if (!(rbv >= 0x000C0000 && rbv <= 0x000F0000 && (rbv % 0x10000 == 0)))
                return false;

            value = unchecked(rbv + offsetImm.Value);
            return true;
        }

        private static HashSet<uint> DetectResourceGetterTargets(List<Instruction> instructions)
        {
            var result = new HashSet<uint>();
            if (instructions == null || instructions.Count == 0)
                return result;

            var counts = new Dictionary<uint, int>();

            for (var i = 0; i < instructions.Count; i++)
            {
                var t = InsText(instructions[i]).Trim();
                var mcall = Regex.Match(t, @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (!mcall.Success)
                    continue;

                if (!TryParseHexUInt(mcall.Groups["target"].Value, out var tgt))
                    continue;

                uint? id = null;
                uint? baseImm = null;

                for (var k = i - 1; k >= 0 && k >= i - 10; k--)
                {
                    var back = InsText(instructions[k]).Trim();
                    if (back.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || back.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                        break;

                    var mmov = Regex.Match(back, @"^mov\s+eax,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (id == null && mmov.Success && TryParseHexUInt(mmov.Groups["imm"].Value, out var vi) && vi < 0x2000)
                    {
                        id = vi;
                        continue;
                    }

                    var madd = Regex.Match(back, @"^add\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (baseImm == null && madd.Success && TryParseHexUInt(madd.Groups["imm"].Value, out var vb) && vb >= 0x000C0000 && vb <= 0x000F0000 && (vb % 0x10000 == 0))
                    {
                        baseImm = vb;
                        continue;
                    }
                }

                if (id.HasValue && baseImm.HasValue)
                {
                    if (!counts.ContainsKey(tgt))
                        counts[tgt] = 0;
                    counts[tgt]++;
                }
            }

            foreach (var kvp in counts)
            {
                // Threshold: show up in multiple places before we treat it as a helper.
                if (kvp.Value >= 3)
                    result.Add(kvp.Key);
            }

            return result;
        }

        private static bool LooksLikePrintfFormat(string s)
        {
            if (string.IsNullOrEmpty(s))
                return false;

            // Basic heuristic: contains a % that isn't only %%
            for (var i = 0; i < s.Length - 1; i++)
            {
                if (s[i] != '%')
                    continue;
                if (s[i + 1] == '%')
                {
                    i++;
                    continue;
                }

                // Skip flags/width/precision
                var j = i + 1;
                while (j < s.Length && "-+ #0".IndexOf(s[j]) >= 0) j++;
                while (j < s.Length && char.IsDigit(s[j])) j++;
                if (j < s.Length && s[j] == '.')
                {
                    j++;
                    while (j < s.Length && char.IsDigit(s[j])) j++;
                }

                if (j < s.Length)
                {
                    var c = s[j];
                    if ("duxXscpfegEGi".IndexOf(c) >= 0)
                        return true;
                }
            }

            return false;
        }

        private static Dictionary<uint, string> CollectGlobalSymbols(List<Instruction> instructions, List<LEFixup> sortedFixups)
        {
            var globals = new Dictionary<uint, string>();
            if (instructions == null || sortedFixups == null || sortedFixups.Count == 0)
                return globals;

            var idx = 0;
            foreach (var ins in instructions)
            {
                var fixupsHere = GetFixupsForInstruction(sortedFixups, ins, ref idx);
                foreach (var f in fixupsHere)
                {
                    // Only globalize memory absolute displacements.
                    if (!f.Value32.HasValue || !f.TargetObject.HasValue)
                        continue;
                    var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                    if (!TryClassifyFixupKind(ins, delta, out var kind) || kind != "disp32")
                        continue;

                    var addr = f.Value32.Value;
                    if (!globals.ContainsKey(addr))
                        globals[addr] = $"g_{addr:X8}";
                }
            }

            return globals;
        }

        private static string ApplyGlobalSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> globals)
        {
            if (string.IsNullOrEmpty(insText) || fixupsHere == null || fixupsHere.Count == 0 || globals == null || globals.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!f.Value32.HasValue || !globals.TryGetValue(f.Value32.Value, out var sym))
                    continue;

                var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                if (!TryClassifyFixupKind(ins, delta, out var kind) || kind != "disp32")
                    continue;

                // SharpDisasm tends to render these as 0x????? (lowercase hex). Replace both just in case.
                var needleLower = $"0x{f.Value32.Value:x}";
                var needleUpper = $"0x{f.Value32.Value:X}";
                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }
    }
}
