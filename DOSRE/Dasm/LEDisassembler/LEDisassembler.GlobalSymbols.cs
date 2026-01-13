using System;
using System.Collections.Generic;
using System.Linq;
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

                // or r, 0x...
                var mor = Regex.Match(t, @"^or\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (mor.Success)
                {
                    var dst = mor.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(mor.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = cur | imm;
                    }
                    continue;
                }

                // and r, 0x...
                var mand = Regex.Match(t, @"^and\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (mand.Success)
                {
                    var dst = mand.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(mand.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = cur & imm;
                    }
                    continue;
                }

                // shl/shr r, 0x...
                var msh = Regex.Match(t, @"^(?<op>shl|shr)\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (msh.Success)
                {
                    var op = msh.Groups["op"].Value;
                    var dst = msh.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(msh.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        var sh = (int)(imm & 0x1F);
                        vals[dst] = op.Equals("shr", StringComparison.OrdinalIgnoreCase)
                            ? (cur >> sh)
                            : unchecked(cur << sh);
                    }
                    continue;
                }

                // lea r, [base+0xdisp] or lea r, [base+disp] or lea r, [base-disp]
                var mlea = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})(?:\s*(?<sign>[\+\-])\s*(?<disp>0x[0-9a-fA-F]+|[0-9]+))?\]$", RegexOptions.IgnoreCase);
                if (mlea.Success)
                {
                    var dst = mlea.Groups["dst"].Value.ToLowerInvariant();
                    var bas = mlea.Groups["base"].Value.ToLowerInvariant();
                    var sign = mlea.Groups["sign"].Value;
                    var dispStr = mlea.Groups["disp"].Value;
                    uint disp = 0;
                    if (!string.IsNullOrEmpty(dispStr))
                    {
                        if (dispStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                            disp = Convert.ToUInt32(dispStr[2..], 16);
                        else
                            disp = uint.Parse(dispStr);
                    }

                    if (known.TryGetValue(bas, out var baseKnown) && baseKnown && vals.TryGetValue(bas, out var baseVal))
                    {
                        known[dst] = true;
                        vals[dst] = sign == "-" ? unchecked(baseVal - disp) : unchecked(baseVal + disp);
                    }
                    else
                    {
                        known[dst] = false;
                    }
                    continue;
                }

                // lea r, [0xabs] or lea r, [abs]
                var mleaAbs = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<abs>0x[0-9a-fA-F]+|[0-9]+)\]$", RegexOptions.IgnoreCase);
                if (mleaAbs.Success)
                {
                    var dst = mleaAbs.Groups["dst"].Value.ToLowerInvariant();
                    var absStr = mleaAbs.Groups["abs"].Value;
                    if (TryParseImm32(absStr, out var abs))
                    {
                        known[dst] = true;
                        vals[dst] = abs;
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

        private static Dictionary<uint, uint> CollectGlobalSymbols(List<Instruction> instructions, List<LEFixup> sortedFixups, List<LEObject> objects = null)
        {
            var result = new Dictionary<uint, uint>();
            if (instructions == null || sortedFixups == null || sortedFixups.Count == 0)
                return result;

            var idx = 0;
            foreach (var ins in instructions)
            {
                var fixupsHere = GetFixupsForInstruction(sortedFixups, ins, ref idx);
                foreach (var f in fixupsHere)
                {
                    if (!TryGetFixupFieldStartDelta32(ins, f, out var delta, out var kind) || (kind != "disp32" && kind != "imm32" && kind != "imm32?"))
                        continue;

                    var siteValue = BitConverter.ToUInt32(ins.Bytes, delta);
                    if (result.ContainsKey(siteValue))
                        continue;

                    // Compute the target linear address.
                    uint targetLinear = siteValue; // Default to site value for external fixups.
                    if (f.TargetObject.HasValue && f.TargetOffset.HasValue && objects != null)
                    {
                        var targetObj = objects.FirstOrDefault(o => o.Index == (uint)f.TargetObject.Value);
                        if (targetObj.Index != 0)
                        {
                            targetLinear = unchecked(targetObj.BaseAddress + f.TargetOffset.Value);
                        }
                    }

                    result[siteValue] = targetLinear;
                }
            }

            return result;
        }

        private static string ApplyGlobalSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> globals, List<LEObject> objects)
        {
            if (string.IsNullOrEmpty(insText) || fixupsHere == null || fixupsHere.Count == 0 || globals == null || globals.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!TryGetFixupFieldStartDelta32(ins, f, out var delta, out var kind) || (kind != "disp32" && kind != "imm32" && kind != "imm32?"))
                    continue;

                // Heuristics to avoid rewriting non-address immediates (common false positives):
                // - "imm32?" is explicitly uncertain, so skip.
                // - Very small imm32 values are overwhelmingly flags/lengths/stack allocs, not addresses.
                // - Stack adjustments are almost never addresses.
                if (kind == "imm32?")
                    continue;

                var raw = BitConverter.ToUInt32(ins.Bytes, delta);

                // Extremely small literals are almost always non-address constants in this codebase.
                // Rewriting them based on fixups can corrupt semantics (e.g. 0xFF masks, small stack alloc sizes).
                if (raw < 0x1000u)
                    continue;

                if (kind == "imm32")
                {
                    // Avoid rewriting stack adjust immediates (e.g. sub esp, 0x58).
                    if (Regex.IsMatch(rewritten, @"\b(sub|add)\s+esp\s*,\s*0x[0-9a-fA-F]+", RegexOptions.IgnoreCase))
                        continue;
                }

                // Determine the symbol name for this target.
                string sym = null;

                // 1) If it's an internal fixup, compute the target linear address and look it up FIRST.
                // This is more accurate than looking up by the raw site value.
                if (f.TargetObject.HasValue && f.TargetOffset.HasValue && objects != null)
                {
                    var targetObj = objects.FirstOrDefault(o => o.Index == (uint)f.TargetObject.Value);
                    if (targetObj.Index != 0)
                    {
                        var targetLinear = unchecked(targetObj.BaseAddress + f.TargetOffset.Value);
                        if (globals.TryGetValue(targetLinear, out var s2))
                        {
                            sym = s2;
                        }
                    }
                }

                // 2) Fallback to site value lookup (for external fixups or cases where site value IS the target linear).
                if (sym == null && globals.TryGetValue(raw, out var s1))
                {
                    sym = s1;
                }

                if (sym == null)
                    continue;

                // SharpDisasm tends to render these as 0x????? (lowercase hex). Replace both just in case.
                var needleLower = $"0x{raw:x}";
                var needleUpper = $"0x{raw:X}";
                
                // Special case for zero: SharpDisasm may just use "0" without 0x.
                if (raw == 0)
                {
                    // Be careful with replacing '0' as it appears in registers, etc.
                    // But if it's a disp32 fixup on a [0], then 0x0 should be there.
                }

                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }
    }
}
