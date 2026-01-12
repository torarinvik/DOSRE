using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string InferPointerishArgSummaryForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive)
        {
            if (instructions == null || startIdx < 0 || endIdxExclusive <= startIdx)
                return string.Empty;

            var ptrArgs = new HashSet<int>();
            var regSource = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(instructions.Count, endIdxExclusive);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();

                // Far-pointer loads: lgs/les/lfs reg, [arg_N]
                var fp = Regex.Match(cooked, @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>arg_(?<idx>[0-9]+))\]\s*$", RegexOptions.IgnoreCase);
                if (fp.Success && int.TryParse(fp.Groups["idx"].Value, out var fpIdx))
                    ptrArgs.Add(fpIdx);

                // Track reg <- [arg_N]
                var m = Regex.Match(cooked, @"^mov\s+(?<reg>e[a-z]{2})\s*,\s*\[arg_(?<idx>[0-9]+)\]\s*$", RegexOptions.IgnoreCase);
                if (m.Success && int.TryParse(m.Groups["idx"].Value, out var argIdx))
                {
                    regSource[m.Groups["reg"].Value.ToLowerInvariant()] = argIdx;
                    continue;
                }

                foreach (var kv in regSource.ToList())
                {
                    var reg = kv.Key;
                    var srcIdx = kv.Value;
                    if (InsTextUsesRegAsMemBase(cooked, reg))
                        ptrArgs.Add(srcIdx);
                    if (InstructionWritesReg(cooked, reg))
                        regSource.Remove(reg);
                }
            }

            if (ptrArgs.Count == 0)
                return string.Empty;

            var shown = ptrArgs.OrderBy(x => x).Take(8).Select(x => $"ptr_arg_{x}").ToList();
            var more = ptrArgs.Count > 8 ? $", ... (+{ptrArgs.Count - 8})" : string.Empty;
            return string.Join(", ", shown) + more;
        }

        private static string CollectInterruptSummaryForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex)
        {
            if (instructions == null || startIdx < 0 || endIdxExclusive <= startIdx)
                return string.Empty;

            var uniq = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ordered = new List<string>();
            var max = Math.Min(instructions.Count, endIdxExclusive);
            for (var i = startIdx; i < max; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (!t.StartsWith("int ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var hint = TryAnnotateInterrupt(instructions, i, stringSymbols, stringPreview, objects, objBytesByIndex);
                var shortHint = ShortenInterruptHintForCase(hint);
                if (string.IsNullOrWhiteSpace(shortHint))
                    continue;
                if (uniq.Add(shortHint))
                    ordered.Add(shortHint);
                if (ordered.Count >= 6)
                    break;
            }

            if (ordered.Count == 0)
                return string.Empty;
            return string.Join(", ", ordered);
        }

        private static string FormatCSketchHeader(
            uint startAddr,
            string protoHint,
            Dictionary<string, string> outLocalAliases,
            Dictionary<string, int> localBitWidths,
            string ptrArgSummary,
            FunctionSummary summary,
            string ioSummary,
            string intSummary,
            string loopSummary)
        {
            static string CapCommaSummary(string summary, int maxItems, int maxLen)
            {
                if (string.IsNullOrWhiteSpace(summary))
                    return string.Empty;

                var s = summary.Trim();
                var items = s.Split(new[] { ", " }, StringSplitOptions.None)
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0)
                    .ToList();

                if (items.Count > maxItems)
                    s = string.Join(", ", items.Take(maxItems)) + ",...";
                else
                    s = string.Join(", ", items);

                if (maxLen > 16 && s.Length > maxLen)
                    s = s.Substring(0, maxLen - 3).TrimEnd() + "...";

                return s;
            }

            var parts = new List<string>();

            if (!string.IsNullOrWhiteSpace(protoHint))
            {
                var p = protoHint.Trim();
                if (p.StartsWith("PROTO:", StringComparison.OrdinalIgnoreCase))
                    p = p.Substring("PROTO:".Length).Trim();
                var semi = p.IndexOf(';');
                if (semi >= 0)
                    p = p.Substring(0, semi).Trim();
                parts.Add($"proto={p}");
            }
            else
            {
                parts.Add($"proto=func_{startAddr:X8}()");
            }

            // Prioritize reconstructability: out-params + pointer-ish args + loops.
            var hasStrongSignals = false;
            if (outLocalAliases != null && outLocalAliases.Count > 0)
            {
                var vals = new List<string>();
                foreach (var kv in outLocalAliases.OrderBy(k => k.Key).Take(8))
                {
                    var alias = kv.Value;
                    if (localBitWidths != null && localBitWidths.TryGetValue(kv.Key, out var bits))
                        alias = UpgradeOutpAliasWithBitWidth(alias, bits);
                    if (!string.IsNullOrWhiteSpace(alias))
                        vals.Add(alias);
                }
                if (vals.Count > 0)
                {
                    parts.Add($"out={string.Join(",", vals)}");
                    hasStrongSignals = true;
                }
            }

            if (!string.IsNullOrWhiteSpace(ptrArgSummary))
            {
                parts.Add($"args={ptrArgSummary}");
                hasStrongSignals = true;
            }

            var intShort = CapCommaSummary(intSummary, maxItems: 1, maxLen: 70);
            if (!string.IsNullOrWhiteSpace(intShort))
            {
                parts.Add($"int={intShort}");
                hasStrongSignals = true;
            }

            var ioShort = CapCommaSummary(ioSummary, maxItems: 1, maxLen: 70);
            if (!string.IsNullOrWhiteSpace(ioShort))
            {
                parts.Add($"io={ioShort}");
                hasStrongSignals = true;
            }

            if (summary != null)
            {
                var hasGlobals = summary.Globals != null && summary.Globals.Count > 0;
                if (hasGlobals)
                    parts.Add($"globals={string.Join(",", summary.Globals.OrderBy(x => x).Take(3))}{(summary.Globals.Count > 3 ? ",..." : string.Empty)}");

                if (!hasStrongSignals && !hasGlobals && summary.Strings != null && summary.Strings.Count > 0)
                    parts.Add($"strings={string.Join(",", summary.Strings.OrderBy(x => x).Take(2))}{(summary.Strings.Count > 2 ? ",..." : string.Empty)}");
            }

            if (!string.IsNullOrWhiteSpace(loopSummary))
            {
                parts.Add(loopSummary);
                hasStrongSignals = true;
            }

            return parts.Count == 0 ? string.Empty : $"C: {string.Join(" | ", parts)}";
        }

        private static string TrySummarizeCaseTargetRole(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            uint targetAddr,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex)
        {
            if (instructions == null || insIndexByAddr == null)
                return string.Empty;
            if (!insIndexByAddr.TryGetValue(targetAddr, out var idx))
                return string.Empty;

            ushort? localDxImm16 = null;
            string localDxSource = null;
            byte? localAlImm8 = null;
            ushort? localAxImm16 = null;
            var localNotes = new List<string>();

            var max = Math.Min(instructions.Count, idx + 28);
            for (var i = idx; i < max; i++)
            {
                var raw = InsText(instructions[i]);
                var cooked = RewriteStackFrameOperands(raw);

                // Lightweight local/flag setup detection (common in switch case handlers).
                if (localNotes.Count < 2 && (i - idx) <= 8)
                {
                    var mMov = Regex.Match(cooked, @"^\s*mov\s+(?:byte|word|dword)\s+\[(?<mem>local_[0-9A-Fa-f]+|g_[0-9A-Fa-f]{8})\]\s*,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
                    if (mMov.Success)
                    {
                        var mem = mMov.Groups["mem"].Value;
                        var imm = mMov.Groups["imm"].Value;
                        if (TryParseHexOrDecUInt32(imm, out var v))
                            localNotes.Add($"set {mem}=0x{v:X}");
                    }

                    if (localNotes.Count < 2)
                    {
                        var mLea = Regex.Match(cooked, @"^\s*lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<mem>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
                        if (mLea.Success)
                        {
                            var reg = mLea.Groups["reg"].Value.ToLowerInvariant();
                            var mem = mLea.Groups["mem"].Value;
                            localNotes.Add($"{reg}=&{mem}");
                        }
                    }
                }

                // Prefer "strong" actions first.
                var intHint = TryAnnotateInterrupt(instructions, i, stringSymbols, stringPreview, objects, objBytesByIndex);
                if (!string.IsNullOrEmpty(intHint))
                {
                    var shortInt = ShortenInterruptHintForCase(intHint);
                    return string.IsNullOrEmpty(shortInt) ? string.Empty : $"INT {shortInt}";
                }

                if (TryParseMovDxImmediate(cooked, out var dxImm))
                {
                    localDxImm16 = dxImm;
                    localDxSource = $"0x{dxImm:X4}";
                }

                if (TryParseMovDxFromMemory(cooked, out var dxMem))
                {
                    localDxImm16 = null;
                    localDxSource = $"[{dxMem}]";
                }

                if (TryParseMovAlImmediate(cooked, out var alImm))
                    localAlImm8 = alImm;
                if (TryParseMovAxImmediate(cooked, out var axImm))
                    localAxImm16 = axImm;

                var ioHint = TryAnnotateIoPortAccess(cooked, localDxImm16, localDxSource, localAlImm8, localAxImm16);
                if (!string.IsNullOrEmpty(ioHint))
                {
                    var shortIo = ShortenIoHintForCase(ioHint);
                    return string.IsNullOrEmpty(shortIo) ? string.Empty : $"IO {shortIo}";
                }

                // Don't scan past an obvious terminal for this tiny summary.
                var t = cooked.TrimStart();
                if (t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp ", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            if (localNotes.Count > 0)
                return string.Join(", ", localNotes);

            return string.Empty;
        }
    }
}
