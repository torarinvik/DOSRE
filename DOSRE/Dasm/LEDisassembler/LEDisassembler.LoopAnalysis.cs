using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private sealed class LoopSummary
        {
            public uint Header;
            public readonly HashSet<uint> Latches = new HashSet<uint>();
            public string InductionVar;
            public int? Step;
            public string Bound;
            public string Cond;
        }

        private static void InferLoopsForFunction(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            List<uint> sortedBlockStarts,
            uint startAddr,
            uint endAddrExclusive,
            int startIdx,
            int endIdxExclusive,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            out List<LoopSummary> loops)
        {
            loops = new List<LoopSummary>();
            if (instructions == null || insIndexByAddr == null)
                return;
            if (startIdx < 0 || endIdxExclusive <= startIdx)
                return;

            var loopByHeader = new Dictionary<uint, LoopSummary>();

            // Back-edges: any branch/cjump to an earlier address within the same function.
            for (var i = startIdx; i < endIdxExclusive; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;
                if (addr < startAddr || addr >= endAddrExclusive)
                    continue;

                List<LEFixup> fixupsHere = null;
                fixupsByInsAddr?.TryGetValue(addr, out fixupsHere);

                if (!TryGetRelativeBranchTarget(ins, fixupsHere, out var target, out var isCall) || isCall)
                    continue;

                if (target < startAddr || target >= endAddrExclusive)
                    continue;

                if (target >= addr)
                    continue;

                if (!loopByHeader.TryGetValue(target, out var ls))
                    loopByHeader[target] = ls = new LoopSummary { Header = target };
                ls.Latches.Add(addr);
            }

            if (loopByHeader.Count == 0)
                return;

            // Helper: find the end of a basic block starting at blockStart.
            uint FindBlockEnd(uint blockStart)
            {
                if (sortedBlockStarts == null || sortedBlockStarts.Count == 0)
                    return endAddrExclusive;

                var idx = sortedBlockStarts.BinarySearch(blockStart);
                idx = idx < 0 ? ~idx : idx + 1;
                while (idx >= 0 && idx < sortedBlockStarts.Count)
                {
                    var b = sortedBlockStarts[idx];
                    if (b <= blockStart)
                    {
                        idx++;
                        continue;
                    }
                    if (b >= endAddrExclusive)
                        break;
                    return b;
                }

                return endAddrExclusive;
            }

            // Induction-var heuristic: look for cmp [local_X], imm near header and inc/add/sub/dec of same local near a latch.
            foreach (var kv in loopByHeader.OrderBy(k => k.Key).Take(8))
            {
                var ls = kv.Value;
                var headerStart = ls.Header;
                var headerEnd = FindBlockEnd(headerStart);
                if (!insIndexByAddr.TryGetValue(headerStart, out var headerIdx))
                    continue;

                var headerStopIdx = endIdxExclusive;
                if (insIndexByAddr.TryGetValue(headerEnd, out var he))
                    headerStopIdx = Math.Min(endIdxExclusive, he);

                string cmpVar = null;
                string cmpImm = null;
                string cmpCond = null;

                // Scan a small window at loop header.
                var scanHeaderMax = Math.Min(headerStopIdx, headerIdx + 24);
                for (var i = headerIdx; i < scanHeaderMax; i++)
                {
                    var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();
                    var mCmpMem = Regex.Match(cooked, @"^cmp\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                    var mCmpReg = Regex.Match(cooked, @"^cmp\s+(?<reg>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                    if (mCmpMem.Success)
                    {
                        cmpVar = mCmpMem.Groups["var"].Value;
                        cmpImm = mCmpMem.Groups["imm"].Value;
                    }
                    else if (mCmpReg.Success)
                    {
                        cmpVar = mCmpReg.Groups["reg"].Value.ToLowerInvariant();
                        cmpImm = mCmpReg.Groups["imm"].Value;
                    }
                    else
                    {
                        continue;
                    }

                    // Look ahead for the branch that uses this cmp.
                    for (var j = i + 1; j < Math.Min(scanHeaderMax, i + 4); j++)
                    {
                        var t = RewriteStackFrameOperands(InsText(instructions[j])).Trim();
                        var sp = t.IndexOf(' ');
                        var mn = (sp > 0 ? t.Substring(0, sp) : t).Trim().ToLowerInvariant();
                        if (!mn.StartsWith("j", StringComparison.OrdinalIgnoreCase) || mn == "jmp")
                            continue;
                        cmpCond = mn;
                        break;
                    }
                    break;
                }

                if (!string.IsNullOrWhiteSpace(cmpVar))
                {
                    // Scan latches for updates.
                    foreach (var latch in ls.Latches.OrderBy(x => x))
                    {
                        if (!insIndexByAddr.TryGetValue(latch, out var latchIdx))
                            continue;

                        var latchEnd = FindBlockEnd(latch);
                        var latchStopIdx = endIdxExclusive;
                        if (insIndexByAddr.TryGetValue(latchEnd, out var le))
                            latchStopIdx = Math.Min(endIdxExclusive, le);

                        var scanLatchMax = Math.Min(latchStopIdx, latchIdx + 20);
                        for (var i = latchIdx; i < scanLatchMax; i++)
                        {
                            var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();

                            if (cmpVar.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
                            {
                                if (Regex.IsMatch(cooked, $@"^inc\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = 1;
                                    break;
                                }
                                if (Regex.IsMatch(cooked, $@"^dec\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = -1;
                                    break;
                                }

                                var mAddMem = Regex.Match(cooked, $@"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddMem.Success)
                                {
                                    if (TryParseHexOrDecUInt32(mAddMem.Groups["imm"].Value, out var u) && u <= 0x100)
                                    {
                                        var step = (int)u;
                                        if (mAddMem.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                            step = -step;
                                        ls.InductionVar = cmpVar;
                                        ls.Step = step;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                if (Regex.IsMatch(cooked, $@"^inc\s+{Regex.Escape(cmpVar)}\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = 1;
                                    break;
                                }
                                if (Regex.IsMatch(cooked, $@"^dec\s+{Regex.Escape(cmpVar)}\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = -1;
                                    break;
                                }

                                var mAddReg = Regex.Match(cooked, $@"^(?<op>add|sub)\s+{Regex.Escape(cmpVar)}\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddReg.Success)
                                {
                                    if (TryParseHexOrDecUInt32(mAddReg.Groups["imm"].Value, out var u) && u <= 0x100)
                                    {
                                        var step = (int)u;
                                        if (mAddReg.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                            step = -step;
                                        ls.InductionVar = cmpVar;
                                        ls.Step = step;
                                        break;
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                                break;
                        }

                        if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                            break;
                    }

                    // Only keep header-derived bound/cond if it also gave us a matching induction update.
                    // Otherwise, it is likely an unrelated in-loop compare.
                    if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                    {
                        ls.Bound = cmpImm;
                        ls.Cond = cmpCond;
                    }
                }

                // Countdown-loop heuristic: look for `dec/inc/add/sub` right before a back-edge jcc,
                // or x86 `loop/loope/loopne` which implies ECX-- and jump while ECX != 0.
                if (string.IsNullOrWhiteSpace(ls.InductionVar) || !ls.Step.HasValue)
                {
                    foreach (var latch in ls.Latches.OrderBy(x => x))
                    {
                        if (!insIndexByAddr.TryGetValue(latch, out var latchIdx))
                            continue;

                        var latchText = RewriteStackFrameOperands(InsText(instructions[latchIdx])).Trim();
                        var sp = latchText.IndexOf(' ');
                        var latchMn = (sp > 0 ? latchText.Substring(0, sp) : latchText).Trim().ToLowerInvariant();

                        // `loop` family
                        if (latchMn == "loop" || latchMn == "loope" || latchMn == "loopz" || latchMn == "loopne" || latchMn == "loopnz")
                        {
                            ls.InductionVar = "ecx";
                            ls.Step = -1;
                            ls.Bound ??= "0";
                            ls.Cond = latchMn;
                            break;
                        }

                        // For conditional branches, try to infer a counter update directly preceding.
                        if (latchMn.StartsWith("j", StringComparison.OrdinalIgnoreCase) && latchMn != "jmp")
                        {
                            // Prefer the actual latch condition.
                            ls.Cond = latchMn;

                            var isEqLatch = latchMn == "jnz" || latchMn == "jne" || latchMn == "jz" || latchMn == "je";

                            // If it's a jnz/jne style back-edge, common idiom is count-down to zero.
                            if ((latchMn == "jnz" || latchMn == "jne") && string.IsNullOrWhiteSpace(ls.Bound))
                                ls.Bound = "0";

                            // Only treat dec/inc/add/sub as a countdown/update hint for equality-style latches.
                            // For other jccs (e.g., jb/jae), the latch usually depends on a preceding cmp, not dec/inc.
                            if (!isEqLatch)
                            {
                                // Non-equality latch heuristic (safe): if the latch is fed by a nearby `cmp lhs, rhs`,
                                // and we see an update of `lhs` shortly before the cmp/jcc, treat `lhs` as the iv.
                                // This catches common idioms like:
                                //   inc edx
                                //   cmp edx, ecx
                                //   jb  header
                                // and avoids using unrelated dec/inc used for string ops unless it participates in cmp.

                                string cmpLhs = null;
                                string cmpRhs = null;
                                var cmpIdx = -1;

                                // Find the closest cmp in a small window before the latch.
                                for (var k = Math.Max(startIdx, latchIdx - 4); k < latchIdx; k++)
                                {
                                    var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();
                                    var mCmpReg = Regex.Match(prev, @"^cmp\s+(?<lhs>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<rhs>0x[0-9A-Fa-f]+|[0-9]+|e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                    var mCmpMem = Regex.Match(prev, @"^cmp\s+(?:byte|word|dword)?\s*\[(?<lhs>local_[0-9A-Fa-f]+)\]\s*,\s*(?<rhs>0x[0-9A-Fa-f]+|[0-9]+|e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                    if (mCmpReg.Success)
                                    {
                                        cmpLhs = mCmpReg.Groups["lhs"].Value.ToLowerInvariant();
                                        cmpRhs = mCmpReg.Groups["rhs"].Value.ToLowerInvariant();
                                        cmpIdx = k;
                                    }
                                    else if (mCmpMem.Success)
                                    {
                                        cmpLhs = mCmpMem.Groups["lhs"].Value;
                                        cmpRhs = mCmpMem.Groups["rhs"].Value.ToLowerInvariant();
                                        cmpIdx = k;
                                    }
                                }

                                if (!string.IsNullOrWhiteSpace(cmpLhs))
                                {
                                    // Find an update of cmpLhs shortly before the latch.
                                    // Prefer scanning before the cmp (not before the jcc), since some patterns have
                                    // setup work between the update and the cmp (e.g. string ops between inc and cmp).
                                    var updateStop = (cmpIdx >= 0 ? cmpIdx : latchIdx);
                                    for (var k = Math.Max(startIdx, updateStop - 12); k < updateStop; k++)
                                    {
                                        var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();

                                        if (cmpLhs.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
                                        {
                                            var esc = Regex.Escape(cmpLhs);
                                            if (Regex.IsMatch(prev, $@"^inc\s+(?:byte|word|dword)?\s*\[{esc}\]\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = 1;
                                                break;
                                            }
                                            if (Regex.IsMatch(prev, $@"^dec\s+(?:byte|word|dword)?\s*\[{esc}\]\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = -1;
                                                break;
                                            }

                                            var mAddMem2 = Regex.Match(prev, $@"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[{esc}\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                            if (mAddMem2.Success && TryParseHexOrDecUInt32(mAddMem2.Groups["imm"].Value, out var u3) && u3 <= 0x100)
                                            {
                                                var step = (int)u3;
                                                if (mAddMem2.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                                    step = -step;
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = step;
                                                break;
                                            }
                                        }
                                        else
                                        {
                                            var esc = Regex.Escape(cmpLhs);
                                            if (Regex.IsMatch(prev, $@"^inc\s+{esc}\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = 1;
                                                break;
                                            }
                                            if (Regex.IsMatch(prev, $@"^dec\s+{esc}\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = -1;
                                                break;
                                            }

                                            var mAddReg2 = Regex.Match(prev, $@"^(?<op>add|sub)\s+{esc}\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                            if (mAddReg2.Success && TryParseHexOrDecUInt32(mAddReg2.Groups["imm"].Value, out var u4) && u4 <= 0x100)
                                            {
                                                var step = (int)u4;
                                                if (mAddReg2.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                                    step = -step;
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = step;
                                                break;
                                            }
                                        }
                                    }

                                    if (!string.IsNullOrWhiteSpace(ls.InductionVar) && ls.Step.HasValue)
                                    {
                                        if (string.IsNullOrWhiteSpace(ls.Bound) && !string.IsNullOrWhiteSpace(cmpRhs))
                                            ls.Bound = cmpRhs;
                                        break;
                                    }
                                }

                                continue;
                            }

                            for (var k = Math.Max(startIdx, latchIdx - 3); k < latchIdx; k++)
                            {
                                var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();

                                // dec/inc reg
                                var mDecReg = Regex.Match(prev, @"^(?<op>dec|inc)\s+(?<reg>e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                if (mDecReg.Success)
                                {
                                    var reg = mDecReg.Groups["reg"].Value.ToLowerInvariant();
                                    var op = mDecReg.Groups["op"].Value.ToLowerInvariant();
                                    ls.InductionVar = reg;
                                    ls.Step = op == "dec" ? -1 : 1;
                                    break;
                                }

                                // dec/inc [local]
                                var mDecMem = Regex.Match(prev, @"^(?<op>dec|inc)\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
                                if (mDecMem.Success)
                                {
                                    var v = mDecMem.Groups["var"].Value;
                                    var op = mDecMem.Groups["op"].Value.ToLowerInvariant();
                                    ls.InductionVar = v;
                                    ls.Step = op == "dec" ? -1 : 1;
                                    break;
                                }

                                // add/sub reg, imm or add/sub [local], imm
                                var mAddReg = Regex.Match(prev, @"^(?<op>add|sub)\s+(?<dst>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddReg.Success && TryParseHexOrDecUInt32(mAddReg.Groups["imm"].Value, out var u1) && u1 <= 0x100)
                                {
                                    var dst = mAddReg.Groups["dst"].Value.ToLowerInvariant();
                                    var step = (int)u1;
                                    if (mAddReg.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                        step = -step;
                                    ls.InductionVar = dst;
                                    ls.Step = step;
                                    break;
                                }

                                var mAddMem = Regex.Match(prev, @"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddMem.Success && TryParseHexOrDecUInt32(mAddMem.Groups["imm"].Value, out var u2) && u2 <= 0x100)
                                {
                                    var dst = mAddMem.Groups["var"].Value;
                                    var step = (int)u2;
                                    if (mAddMem.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                        step = -step;
                                    ls.InductionVar = dst;
                                    ls.Step = step;
                                    break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(ls.InductionVar) && ls.Step.HasValue)
                                break;
                        }
                    }
                }

                loops.Add(ls);
            }
        }

        private static string FormatLoopSummaryForFunction(List<LoopSummary> loops)
        {
            if (loops == null || loops.Count == 0)
                return string.Empty;

            var parts = new List<string>();
            var idx = 0;
            foreach (var l in loops.Take(3))
            {
                // Keep the first loop detailed; subsequent loops are compact to avoid line wrap.
                var latch = (idx == 0 && l.Latches.Count > 0) ? $" latch=0x{l.Latches.Min():X8}" : string.Empty;
                var iv = (idx == 0 && !string.IsNullOrWhiteSpace(l.InductionVar)) ? $" iv={l.InductionVar}" : string.Empty;
                var step = (idx == 0 && l.Step.HasValue) ? $" step={(l.Step.Value >= 0 ? "+" : string.Empty)}{l.Step.Value}" : string.Empty;
                var bound = !string.IsNullOrWhiteSpace(l.Bound) ? $" bound={l.Bound}" : string.Empty;
                var cond = !string.IsNullOrWhiteSpace(l.Cond) ? $" cond={l.Cond}" : string.Empty;
                parts.Add($"hdr=0x{l.Header:X8}{latch}{iv}{step}{bound}{cond}");
                idx++;
            }

            var more = loops.Count > 3 ? $", ... (+{loops.Count - 3})" : string.Empty;
            return $"LOOPS: {string.Join(", ", parts)}{more}";
        }

        private static string FormatLoopHeaderHint(LoopSummary loop)
        {
            if (loop == null)
                return string.Empty;

            var latch = loop.Latches.Count > 0 ? $"latch=0x{loop.Latches.Min():X8}" : string.Empty;
            var iv = !string.IsNullOrWhiteSpace(loop.InductionVar) ? $"iv={loop.InductionVar}" : string.Empty;
            var step = loop.Step.HasValue ? $"step={(loop.Step.Value >= 0 ? "+" : string.Empty)}{loop.Step.Value}" : string.Empty;
            var bound = !string.IsNullOrWhiteSpace(loop.Bound) ? $"bound={loop.Bound}" : string.Empty;
            var cond = !string.IsNullOrWhiteSpace(loop.Cond) ? $"cond={loop.Cond}" : string.Empty;
            var parts = new[] { latch, iv, step, bound, cond }.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            return parts.Count == 0 ? "LOOPHDR" : $"LOOPHDR: {string.Join(" ", parts)}";
        }
    }
}
