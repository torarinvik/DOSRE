using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using DOSRE.Analysis;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static readonly object _lastAnalysisLock = new object();
        private static LeAnalysis _lastAnalysis;

        public static LeAnalysis GetLastAnalysis()
        {
            lock (_lastAnalysisLock)
                return _lastAnalysis;
        }

        private static void SetLastAnalysis(LeAnalysis analysis)
        {
            lock (_lastAnalysisLock)
                _lastAnalysis = analysis;
        }

        // SharpDisasm's default Instruction.ToString() path uses shared translator state.
        // For parallel insights passes, use a per-thread translator instance.
        private static readonly ThreadLocal<SharpDisasm.Translators.Translator> _tlsIntelTranslator =
            new ThreadLocal<SharpDisasm.Translators.Translator>(() => new SharpDisasm.Translators.IntelTranslator());

        private static string InsText(Instruction ins)
        {
            if (ins == null)
                return string.Empty;

            try
            {
                var tr = _tlsIntelTranslator.Value;
                if (tr != null)
                    return tr.Translate(ins) ?? string.Empty;
            }
            catch
            {
                // Fallback for any unexpected translator failure.
            }

            // Avoid Instruction.ToString() here (not thread-safe under parallel insights).
            return string.Empty;
        }

        private sealed class FunctionSummary
        {
            public uint Start;
            public int InstructionCount;
            public int BlockCount;
            public readonly HashSet<uint> Calls = new HashSet<uint>();
            public readonly HashSet<string> Globals = new HashSet<string>(StringComparer.Ordinal);
            public readonly HashSet<string> Strings = new HashSet<string>(StringComparer.Ordinal);
            public readonly HashSet<ushort> IoPorts = new HashSet<ushort>();

            public string ToComment()
            {
                var calls = Calls.Count > 0 ? string.Join(", ", Calls.OrderBy(x => x).Take(12).Select(x => $"func_{x:X8}")) : "(none)";
                var globs = Globals.Count > 0 ? string.Join(", ", Globals.OrderBy(x => x).Take(12)) : "(none)";
                var strs = Strings.Count > 0 ? string.Join(", ", Strings.OrderBy(x => x).Take(12)) : "(none)";
                var ioports = IoPorts.Count > 0 ? string.Join(", ", IoPorts.OrderBy(x => x).Take(6).Select(x => KnownIoPorts.TryGetValue(x, out var name) ? $"{name}(0x{x:X})" : $"0x{x:X}")) : "(none)";
                return $"; SUMMARY: ins={InstructionCount} blocks={BlockCount} calls={calls} globals={globs} strings={strs} IO={ioports}";
            }
        }

        private static readonly Regex EbpDispRegex = new Regex(
            "\\[(?<reg>ebp)\\s*(?<sign>[\\+\\-])\\s*(?<hex>0x[0-9A-Fa-f]+)\\]",
            RegexOptions.Compiled);
        private static readonly Regex MovRegRegRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<src>e[a-z]{2})$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MovRegFromArgRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*\[arg_(?<arg>[0-9]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MovRegFromEbpDispRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*\[ebp\s*\+\s*(?<hex>0x[0-9A-Fa-f]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex LeaRegFromArgRegex = new Regex(
            @"^lea\s+(?<dst>e[a-z]{2}),\s*\[arg_(?<arg>[0-9]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex WritesRegRegex = new Regex(
            @"^(?<mn>mov|lea|add|sub|xor|and|or|imul|shl|shr|sar|rol|ror|inc|dec|pop|xchg)\s+(?<dst>e[a-z]{2})\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpRegex = new Regex(
            @"\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpIndexedRegex = new Regex(
            @"\[(?<base>e[a-z]{2})(?:\+(?<index>e[a-z]{2})\*(?<scale>[0-9]+))?(?:(?<sign>[\+\-])0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpWithSizeRegex = new Regex(
            @"(?<size>byte|word|dword)\s+\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovDxImm16Regex = new Regex(
            @"^mov\s+dx,\s*(?<imm>0x[0-9A-Fa-f]+)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovEdxImmRegex = new Regex(
            @"^mov\s+edx,\s*(?<imm>0x[0-9A-Fa-f]+)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex OutDxAlRegex = new Regex(
            @"^out\s+dx,\s*al$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex OutDxAxRegex = new Regex(
            @"^out\s+dx,\s*ax$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex InAlDxRegex = new Regex(
            @"^in\s+al,\s*dx$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static void SplitInstructionAndComments(string insText, out string instruction, out List<string> comments)
        {
            instruction = insText ?? string.Empty;
            comments = new List<string>();
            if (string.IsNullOrEmpty(insText))
                return;

            var parts = insText.Split(new[] { " ; " }, StringSplitOptions.None);
            if (parts.Length <= 1)
                return;

            instruction = parts[0];
            comments = parts.Skip(1).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToList();
        }

        private static IEnumerable<string> WrapText(string text, int maxWidth)
        {
            if (string.IsNullOrEmpty(text))
                yield break;

            if (maxWidth <= 8)
            {
                yield return text;
                yield break;
            }

            var t = text.Trim();
            while (t.Length > maxWidth)
            {
                var breakAt = t.LastIndexOf(' ', maxWidth);
                if (breakAt <= 0)
                    breakAt = maxWidth;

                var line = t[..breakAt].TrimEnd();
                if (!string.IsNullOrEmpty(line))
                    yield return line;

                t = t[breakAt..].TrimStart();
            }

            if (t.Length > 0)
                yield return t;
        }

        private static void AppendWrappedDisasmLine(StringBuilder sb, string prefix, string insText, int commentColumn, int maxWidth, int minGapAfterInstruction = 14)
        {
            if (sb == null)
                return;

            SplitInstructionAndComments(insText, out var instruction, out var comments);
            var baseLine = (prefix ?? string.Empty) + (instruction ?? string.Empty);
            if (comments == null || comments.Count == 0)
            {
                sb.AppendLine(baseLine);
                return;
            }

            var startCol = Math.Max(0, commentColumn);
            if (!string.IsNullOrEmpty(baseLine) && baseLine.Length >= startCol)
                startCol = baseLine.Length + Math.Max(1, minGapAfterInstruction);

            var commentIndent = new string(' ', startCol);
            var first = true;

            foreach (var c in comments)
            {
                foreach (var wrapped in WrapText(c, Math.Max(16, maxWidth - (startCol + 2))))
                {
                    if (first)
                    {
                        var line = baseLine;
                        if (line.Length < startCol)
                            line += new string(' ', startCol - line.Length);
                        else if (!string.IsNullOrEmpty(line))
                            line += new string(' ', Math.Max(1, minGapAfterInstruction));
                        line += $"; {wrapped}";
                        sb.AppendLine(line);
                        first = false;
                    }
                    else
                    {
                        sb.AppendLine($"{commentIndent}; {wrapped}");
                    }
                }
            }
        }

        private sealed class FieldAccessStats
        {
            public int ReadCount;
            public int WriteCount;
            public string Size = string.Empty;
            public int PointerUseCount;
            public readonly Dictionary<int, int> IndexScaleCounts = new Dictionary<int, int>();
            public readonly Dictionary<uint, int> ArrayBoundCounts = new Dictionary<uint, int>();
        }

        private static void RecordFieldIndexScale(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            int scale)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias) || scale <= 0)
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.IndexScaleCounts.TryGetValue(scale, out var c);
            st.IndexScaleCounts[scale] = c + 1;
        }

        private static int? GetMostCommonIndexScale(FieldAccessStats st)
        {
            if (st == null || st.IndexScaleCounts == null || st.IndexScaleCounts.Count == 0)
                return null;

            // Require at least 2 hits to avoid noisy one-offs.
            var best = st.IndexScaleCounts.OrderByDescending(k => k.Value).ThenBy(k => k.Key).FirstOrDefault();
            return best.Value >= 2 ? best.Key : null;
        }

        private static uint? GetMostCommonArrayBound(FieldAccessStats st)
        {
            if (st == null || st.ArrayBoundCounts == null || st.ArrayBoundCounts.Count == 0)
                return null;

            var best = st.ArrayBoundCounts.OrderByDescending(k => k.Value).ThenBy(k => k.Key).FirstOrDefault();
            if (best.Value >= 2)
                return best.Key;

            // If we only ever saw one bound value for this field, a single hit can still be useful.
            // (Keeps things conservative: avoids emitting when multiple different bounds were observed.)
            return st.ArrayBoundCounts.Count == 1 && best.Value >= 1 ? best.Key : null;
        }

        private static void RecordFieldArrayBound(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            uint bound)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias))
                return;
            if (bound == 0 || bound > 0x100000)
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();
            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.ArrayBoundCounts.TryGetValue(bound, out var c);
            st.ArrayBoundCounts[bound] = c + 1;
        }

        private static string FormatFieldExtraHints(FieldAccessStats st)
        {
            if (st == null)
                return string.Empty;

            var hints = new List<string>();

            var ptr = st.PointerUseCount > 0 && (string.IsNullOrEmpty(st.Size) || string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase));
            if (ptr)
                hints.Add("ptr");

            var scale = GetMostCommonIndexScale(st);
            if (scale.HasValue)
                hints.Add($"arr*{scale.Value}");

            var bound = GetMostCommonArrayBound(st);
            if (bound.HasValue)
                hints.Add($"n~0x{bound.Value:X}");

            return hints.Count == 0 ? string.Empty : " " + string.Join(" ", hints);
        }

        private static string BitWidthToMemSize(int bits)
        {
            return bits switch
            {
                8 => "byte",
                16 => "word",
                32 => "dword",
                _ => string.Empty
            };
        }

        private static string InferMemOperandSize(string insText, string memOperandText)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(memOperandText))
                return string.Empty;

            // Prefer explicit size tokens close to the memory operand.
            var m = Regex.Match(insText, $@"\b(?<sz>byte|word|dword)\s*{Regex.Escape(memOperandText)}\b", RegexOptions.IgnoreCase);
            if (m.Success)
                return m.Groups["sz"].Value.ToLowerInvariant();

            // Best-effort: infer from register operand width for common ops.
            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = sp > 0 ? t.Substring(0, sp).ToLowerInvariant() : t.ToLowerInvariant();

            // movzx/movsx source width should be explicit; don't guess.
            if (mnemonic == "movzx" || mnemonic == "movsx")
                return string.Empty;

            var ops = sp > 0 ? t.Substring(sp + 1) : string.Empty;
            var parts = ops.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            if (parts.Count < 2)
                return string.Empty;

            var op0 = parts[0];
            var memIsDest = op0.Contains(memOperandText, StringComparison.OrdinalIgnoreCase);
            var other = memIsDest ? parts[1] : parts[0];
            var bits = GetRegBitWidth(other);
            return bits.HasValue ? BitWidthToMemSize(bits.Value) : string.Empty;
        }

        private static bool TryParseEbpArgIndex(string hex, out int argIndex)
        {
            argIndex = -1;
            if (!TryParseHexUInt(hex, out var offU))
                return false;

            var off = (int)offU;
            if (off < 8)
                return false;
            if ((off - 8) % 4 != 0)
                return false;
            argIndex = (off - 8) / 4;
            return argIndex >= 0;
        }

        private static void UpdatePointerAliases(string insText, Dictionary<string, string> aliases, Dictionary<uint, string> ptrSymbols = null)
        {
            if (aliases == null || string.IsNullOrEmpty(insText))
                return;

            // Normalize spacing a bit for regexes.
            var t = insText.Trim();

            // Propagate pointer aliases: mov dst, src
            var mrr = MovRegRegRegex.Match(t);
            if (mrr.Success)
            {
                var dst = mrr.Groups["dst"].Value.ToLowerInvariant();
                var src = mrr.Groups["src"].Value.ToLowerInvariant();
                if (aliases.TryGetValue(src, out var a))
                    aliases[dst] = a;
                else
                    aliases.Remove(dst);
                return;
            }

            // mov dst, [arg_N]
            var mfa = MovRegFromArgRegex.Match(t);
            if (mfa.Success)
            {
                var dst = mfa.Groups["dst"].Value.ToLowerInvariant();
                var arg = mfa.Groups["arg"].Value;
                aliases[dst] = $"arg{arg}";
                return;
            }

            // lea dst, [arg_N]
            var lfa = LeaRegFromArgRegex.Match(t);
            if (lfa.Success)
            {
                var dst = lfa.Groups["dst"].Value.ToLowerInvariant();
                var arg = lfa.Groups["arg"].Value;
                aliases[dst] = $"arg{arg}";
                return;
            }

            // mov dst, [ebp+0xNN] (before stack rewrite) => argK if it matches a typical arg slot
            var mebp = MovRegFromEbpDispRegex.Match(t);
            if (mebp.Success)
            {
                var dst = mebp.Groups["dst"].Value.ToLowerInvariant();
                var hex = mebp.Groups["hex"].Value;
                if (TryParseEbpArgIndex(hex, out var argIndex))
                {
                    aliases[dst] = $"arg{argIndex}";
                    return;
                }
            }

            // mov dst, [abs] => if abs is an inferred pointer global, treat dst as that pointer base
            if (ptrSymbols != null && ptrSymbols.Count > 0)
            {
                if (TryParseMovRegFromAbs(t, out var dstReg, out var abs) && ptrSymbols.TryGetValue(abs, out var ptrName))
                {
                    aliases[dstReg] = ptrName;
                    return;
                }
            }

            // If instruction writes to a register in some other way, drop its alias to avoid staleness.
            var wr = WritesRegRegex.Match(t);
            if (wr.Success)
            {
                var dst = wr.Groups["dst"].Value.ToLowerInvariant();
                if (dst != "ecx")
                    aliases.Remove(dst);
            }
        }

        private static void RecordFieldAccess(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            int readInc,
            int writeInc,
            string size)
        {
            if (statsByBase == null || string.IsNullOrEmpty(baseAlias))
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            if (!string.IsNullOrEmpty(size) && string.IsNullOrEmpty(st.Size))
                st.Size = size;
            else if (!string.IsNullOrEmpty(size) && !string.IsNullOrEmpty(st.Size) && !string.Equals(st.Size, size, StringComparison.OrdinalIgnoreCase))
                st.Size = string.Empty;

            if (readInc > 0)
                st.ReadCount += readInc;
            if (writeInc > 0)
                st.WriteCount += writeInc;
        }

        private static void RecordFieldPointerUse(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias))
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.PointerUseCount++;
        }

        private static void GetMemAccessRW(string insText, string memOperandText, out int reads, out int writes)
        {
            reads = 0;
            writes = 0;

            if (string.IsNullOrEmpty(insText) || string.IsNullOrEmpty(memOperandText))
                return;

            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = sp > 0 ? t.Substring(0, sp).ToLowerInvariant() : t.ToLowerInvariant();

            // Split operands roughly (best-effort).
            var ops = sp > 0 ? t.Substring(sp + 1) : string.Empty;
            var parts = ops.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            var op0 = parts.Count > 0 ? parts[0] : string.Empty;

            var memIsDest = !string.IsNullOrEmpty(op0) && op0.Contains(memOperandText, StringComparison.OrdinalIgnoreCase);

            // Treat various instruction families.
            if (mnemonic == "mov")
            {
                if (memIsDest)
                    writes = 1;
                else
                    reads = 1;
                return;
            }

            switch (mnemonic)
            {
                // Read-modify-write when memory is destination.
                case "add":
                case "sub":
                case "and":
                case "or":
                case "xor":
                case "adc":
                case "sbb":
                case "imul":
                case "shl":
                case "shr":
                case "sar":
                case "rol":
                case "ror":
                case "inc":
                case "dec":
                case "xchg":
                    if (memIsDest)
                    {
                        reads = 1;
                        writes = 1;
                    }
                    else
                    {
                        reads = 1;
                    }
                    return;

                case "cmp":
                case "test":
                    reads = 1;
                    return;

                default:
                    reads = 1;
                    return;
            }
        }

        private static void CollectFieldAccessesForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive,
            out Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            Dictionary<uint, string> ptrSymbols = null)
        {
            statsByBase = new Dictionary<string, Dictionary<uint, FieldAccessStats>>(StringComparer.Ordinal);
            if (instructions == null || startIdx < 0 || endIdxExclusive > instructions.Count || startIdx >= endIdxExclusive)
                return;

            // Track pointer-ish aliases: ecx is likely this.
            var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ecx"] = "this"
            };

            var regFromField = new Dictionary<string, (string baseAlias, uint disp)>(StringComparer.OrdinalIgnoreCase);

            static uint? FindNearbyCmpImmBoundForIndex(List<Instruction> insList, int idx, int start, int end, string indexReg)
            {
                if (insList == null || string.IsNullOrWhiteSpace(indexReg))
                    return null;
                static string CanonReg(string r)
                {
                    if (string.IsNullOrWhiteSpace(r))
                        return string.Empty;
                    r = r.Trim().ToLowerInvariant();
                    return r switch
                    {
                        "al" or "ah" or "ax" or "eax" => "eax",
                        "bl" or "bh" or "bx" or "ebx" => "ebx",
                        "cl" or "ch" or "cx" or "ecx" => "ecx",
                        "dl" or "dh" or "dx" or "edx" => "edx",
                        "si" or "esi" => "esi",
                        "di" or "edi" => "edi",
                        _ => r,
                    };
                }

                indexReg = CanonReg(indexReg);
                if (indexReg == "esp" || indexReg == "ebp")
                    return null;

                // Most bounds checks happen before the indexed access; scan backward a bit.
                var lo = Math.Max(start, idx - 96);
                var candidateRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { indexReg };
                var candidateStackSyms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Track (best-effort) constants loaded into registers within the scan window so we can
                // treat `cmp idx, regConst` as a bounds check.
                var regConst = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
                var regClobbered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Track constants stored into stack locals/args so we can match `cmp idx, [local]`.
                var stackConst = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
                var stackClobbered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Prefer cmp-based bounds (direct checks) over mask-based bounds.
                (uint bound, int distance)? bestCmp = null;
                (uint bound, int distance)? bestMask = null;

                static bool TryMaskToBound(uint mask, out uint bound)
                {
                    bound = 0;
                    if (mask == 0)
                        return false;
                    // mask is (2^k - 1) iff mask & (mask+1) == 0
                    var plus = mask + 1;
                    if ((mask & plus) != 0)
                        return false;
                    bound = plus;
                    return true;
                }

                static void RecordBest(ref (uint bound, int distance)? best, uint bound, int distance)
                {
                    if (bound == 0)
                        return;
                    if (best == null || distance < best.Value.distance)
                        best = (bound, distance);
                }
                for (var j = idx - 1; j >= lo; j--)
                {
                    var t = InsText(insList[j]).Trim();
                    if (t.Length == 0)
                        continue;

                    var dist = idx - j;

                    // Don't scan across clear control-flow boundaries.
                    if (t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp ", StringComparison.OrdinalIgnoreCase))
                        break;

                    // Bounds by bitmask: `and idx, (2^k-1)` implies idx in [0..(2^k-1)], so n = 2^k.
                    // This is common when indexing fixed-size tables.
                    var andRegImm = Regex.Match(
                        t,
                        @"^and\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (andRegImm.Success)
                    {
                        var rr = CanonReg(andRegImm.Groups["reg"].Value);
                        if (candidateRegs.Contains(rr) && TryParseHexOrDecUInt32(andRegImm.Groups["imm"].Value, out var mask) && TryMaskToBound(mask, out var b) && b > 0)
                            RecordBest(ref bestMask, b, dist);
                    }

                    var andStackImm = Regex.Match(
                        t,
                        @"^and\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (andStackImm.Success)
                    {
                        var sym = andStackImm.Groups["sym"].Value;
                        if (candidateStackSyms.Contains(sym) && TryParseHexOrDecUInt32(andStackImm.Groups["imm"].Value, out var mask) && TryMaskToBound(mask, out var b) && b > 0)
                            RecordBest(ref bestMask, b, dist);
                    }

                    // Stack slot constants.
                    var movStackImm = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackImm.Success)
                    {
                        var sym = movStackImm.Groups["sym"].Value;
                        if (!stackConst.ContainsKey(sym) && !stackClobbered.Contains(sym))
                        {
                            if (TryParseHexOrDecUInt32(movStackImm.Groups["imm"].Value, out var su) && su > 0)
                                stackConst[sym] = su;
                            else
                                stackClobbered.Add(sym);
                        }
                    }

                    var movStackReg = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackReg.Success)
                    {
                        var sym = movStackReg.Groups["sym"].Value;
                        if (!stackConst.ContainsKey(sym) && !stackClobbered.Contains(sym))
                        {
                            var src = CanonReg(movStackReg.Groups["src"].Value);
                            if (regConst.TryGetValue(src, out var ru) && ru > 0)
                                stackConst[sym] = ru;
                            else
                                stackClobbered.Add(sym);
                        }
                    }

                    // Record immediate constants assigned to registers.
                    // Because we're scanning backward, only accept the *first* assignment we see for a reg
                    // (i.e., closest to the use), and ignore if we've seen other writes to that reg.
                    var movImm = Regex.Match(
                        t,
                        @"^mov\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movImm.Success)
                    {
                        var dst = CanonReg(movImm.Groups["dst"].Value);
                        if (!regConst.ContainsKey(dst) && !regClobbered.Contains(dst))
                        {
                            if (TryParseHexOrDecUInt32(movImm.Groups["imm"].Value, out var u) && u > 0)
                                regConst[dst] = u;
                            else
                                regClobbered.Add(dst);
                        }
                    }

                    // Track other simple writes that should invalidate constant provenance.
                    var writesReg = Regex.Match(
                        t,
                        @"^(?:add|sub|imul|idiv|div|and|or|xor|shl|shr|sar|rol|ror|inc|dec|lea|pop)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\b",
                        RegexOptions.IgnoreCase);
                    if (writesReg.Success)
                    {
                        var dst = CanonReg(writesReg.Groups["dst"].Value);
                        if (!regConst.ContainsKey(dst))
                            regClobbered.Add(dst);
                    }

                    // Track reg <-> [local_X]/[arg_Y] so we can match cmp [local_X], imm style bounds checks.
                    // Keep this conservative: only stack symbols (locals/args), not arbitrary memory.
                    var movRegFromStack = Regex.Match(
                        t,
                        @"^(?:mov|movsx|movzx)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*$",
                        RegexOptions.IgnoreCase);
                    if (movRegFromStack.Success)
                    {
                        var dst = CanonReg(movRegFromStack.Groups["dst"].Value);
                        var sym = movRegFromStack.Groups["sym"].Value;
                        if (candidateRegs.Contains(dst))
                            candidateStackSyms.Add(sym);
                    }

                    var movStackFromReg = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackFromReg.Success)
                    {
                        var src = CanonReg(movStackFromReg.Groups["src"].Value);
                        var sym = movStackFromReg.Groups["sym"].Value;
                        if (candidateRegs.Contains(src))
                            candidateStackSyms.Add(sym);
                    }

                    // Track simple register-to-register moves so we can match a cmp against a source reg.
                    var mv = Regex.Match(
                        t,
                        @"^(?:mov|movsx|movzx)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (mv.Success)
                    {
                        var dst = CanonReg(mv.Groups["dst"].Value);
                        var src = CanonReg(mv.Groups["src"].Value);
                        if (candidateRegs.Contains(dst))
                            candidateRegs.Add(src);
                    }

                    var m = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);

                    if (m.Success)
                    {
                        var reg = CanonReg(m.Groups["reg"].Value);
                        if (candidateRegs.Contains(reg) && TryParseHexOrDecUInt32(m.Groups["imm"].Value, out var u) && u > 0)
                            RecordBest(ref bestCmp, u, dist);
                        continue;
                    }

                    // cmp <reg>, <regConst>
                    var mrr = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<r1>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?(?<r2>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (mrr.Success)
                    {
                        var r1 = CanonReg(mrr.Groups["r1"].Value);
                        var r2 = CanonReg(mrr.Groups["r2"].Value);
                        if (candidateRegs.Contains(r1) && regConst.TryGetValue(r2, out var b) && b > 0)
                            RecordBest(ref bestCmp, b, dist);
                        if (candidateRegs.Contains(r2) && regConst.TryGetValue(r1, out var b2) && b2 > 0)
                            RecordBest(ref bestCmp, b2, dist);
                        continue;
                    }

                    // cmp <candidateReg>, [stackSymConst]
                    var mrs = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*$",
                        RegexOptions.IgnoreCase);
                    if (mrs.Success)
                    {
                        var rr = CanonReg(mrs.Groups["reg"].Value);
                        var sym = mrs.Groups["sym"].Value;
                        if (candidateRegs.Contains(rr) && candidateStackSyms.Contains(sym) && stackConst.TryGetValue(sym, out var b4) && b4 > 0)
                            RecordBest(ref bestCmp, b4, dist);
                        continue;
                    }

                    // cmp [stackSymConst], <candidateReg>
                    var msr2 = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (msr2.Success)
                    {
                        var sym = msr2.Groups["sym"].Value;
                        var rr = CanonReg(msr2.Groups["reg"].Value);
                        if (candidateRegs.Contains(rr) && candidateStackSyms.Contains(sym) && stackConst.TryGetValue(sym, out var b5) && b5 > 0)
                            RecordBest(ref bestCmp, b5, dist);
                        continue;
                    }

                    var m2 = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (!m2.Success)
                    {
                        // cmp [stackSym], regConst
                        var msr = Regex.Match(
                            t,
                            @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                            RegexOptions.IgnoreCase);
                        if (msr.Success)
                        {
                            var sym = msr.Groups["sym"].Value;
                            var rr = CanonReg(msr.Groups["reg"].Value);
                            if (candidateStackSyms.Contains(sym) && regConst.TryGetValue(rr, out var b3) && b3 > 0)
                                RecordBest(ref bestCmp, b3, dist);
                        }
                        continue;
                    }

                    var sym2 = m2.Groups["sym"].Value;
                    if (!candidateStackSyms.Contains(sym2))
                        continue;

                    if (TryParseHexOrDecUInt32(m2.Groups["imm"].Value, out var u2) && u2 > 0)
                        RecordBest(ref bestCmp, u2, dist);
                }

                if (bestCmp.HasValue)
                    return bestCmp.Value.bound;

                // Mask-derived bounds are weaker; require they be reasonably close to the access.
                if (bestMask.HasValue && bestMask.Value.distance <= 16)
                    return bestMask.Value.bound;

                return null;
            }

            for (var i = startIdx; i < endIdxExclusive; i++)
            {
                var insText = InsText(instructions[i]).Trim();

                // Update aliases first so we model dataflow forward.
                UpdatePointerAliases(insText, aliases, ptrSymbols);

                // If instruction writes to a register in some other way, drop reg->field provenance.
                var wr = WritesRegRegex.Match(insText);
                if (wr.Success)
                {
                    var dst = wr.Groups["dst"].Value.ToLowerInvariant();
                    regFromField.Remove(dst);
                }

                // Seed provenance on simple loads: mov reg32, [base+disp]
                var mLoad = Regex.Match(insText, @"^mov\s+(?<dst>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<mem>\[[^\]]+\])\s*$", RegexOptions.IgnoreCase);
                if (mLoad.Success)
                {
                    var dst = mLoad.Groups["dst"].Value.ToLowerInvariant();
                    if (GetRegBitWidth(dst).GetValueOrDefault() == 32)
                    {
                        var mem = mLoad.Groups["mem"].Value;
                        var mm = MemOpRegex.Match(mem);
                        if (mm.Success)
                        {
                            var baseReg = mm.Groups["base"].Value.ToLowerInvariant();
                            if (baseReg != "esp" && baseReg != "ebp")
                            {
                                if (!aliases.TryGetValue(baseReg, out var baseAlias))
                                    baseAlias = baseReg == "ecx" ? "this" : null;

                                if (!string.IsNullOrEmpty(baseAlias))
                                {
                                    var disp = 0u;
                                    if (mm.Groups["disp"].Success)
                                        disp = Convert.ToUInt32(mm.Groups["disp"].Value, 16);
                                    if (disp <= 0x4000)
                                        regFromField[dst] = (baseAlias, disp);
                                }
                            }
                        }
                    }
                }

                foreach (Match m in MemOpIndexedRegex.Matches(insText))
                {
                    var baseReg = m.Groups["base"].Value.ToLowerInvariant();
                    if (baseReg == "esp" || baseReg == "ebp")
                        continue;

                    if (regFromField.TryGetValue(baseReg, out var srcField))
                        RecordFieldPointerUse(statsByBase, srcField.baseAlias, srcField.disp);

                    if (!aliases.TryGetValue(baseReg, out var baseAlias))
                    {
                        if (baseReg == "ecx")
                            baseAlias = "this";
                        else
                            continue;
                    }

                    var disp = 0u;
                    if (m.Groups["disp"].Success)
                    {
                        disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);
                        if (m.Groups["sign"].Success && m.Groups["sign"].Value == "-")
                        {
                            // Negative displacements aren't meaningful as struct fields.
                            continue;
                        }
                    }

                    // Avoid treating huge displacements as struct fields; these are often absolute tables
                    // or misclassified addressing modes.
                    if (disp > 0x4000)
                        continue;

                    // Best-effort per-operand read/write classification.
                    var memText = m.Value; // e.g. [ecx+0x10]
                    GetMemAccessRW(insText, memText, out var r, out var w);
                    var size = InferMemOperandSize(insText, memText);
                    RecordFieldAccess(statsByBase, baseAlias, disp, r, w, size);

                    if (m.Groups["index"].Success && m.Groups["scale"].Success && int.TryParse(m.Groups["scale"].Value, out var scale) && (scale == 2 || scale == 4 || scale == 8))
                    {
                        RecordFieldIndexScale(statsByBase, baseAlias, disp, scale);

                        // If we can see a repeated compare against a constant on the index, treat it as an array bound candidate.
                        var idxReg = m.Groups["index"].Value.ToLowerInvariant();
                        var bound = FindNearbyCmpImmBoundForIndex(instructions, i, startIdx, endIdxExclusive, idxReg);
                        if (bound.HasValue)
                            RecordFieldArrayBound(statsByBase, baseAlias, disp, bound.Value);
                    }
                }
            }
        }

        private static string FormatFieldSummary(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            // Keep it compact: show up to 2 bases, 6 fields each.
            var parts = new List<string>();
            foreach (var baseKvp in statsByBase.OrderByDescending(k => k.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount)).ThenBy(k => k.Key).Take(2))
            {
                var baseAlias = baseKvp.Key;
                var fields = baseKvp.Value
                    // De-noise: drop field_0 unless it looks like a dword vptr/first-field.
                    .Where(k =>
                    {
                        if (k.Key != 0)
                            return true;
                        var st = k.Value;
                        if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                            return true;
                        // If size is unknown, allow only low-frequency field_0.
                        var tot = st.ReadCount + st.WriteCount;
                        return string.IsNullOrEmpty(st.Size) && tot <= 8;
                    })
                    .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                    .ThenBy(k => k.Key)
                    .Take(6)
                    .Select(k =>
                    {
                        var disp = k.Key;
                        var st = k.Value;
                        var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                        var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                        var extra = FormatFieldExtraHints(st);
                        return $"+0x{disp:X}({rw}{sz}{extra})";
                    });
                parts.Add($"{baseAlias}: {string.Join(", ", fields)}");
            }

            if (parts.Count == 0)
                return string.Empty;
            return $"FIELDS: {string.Join(" | ", parts)}";
        }

        private static void MergeFieldStats(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> dst,
            Dictionary<string, Dictionary<uint, FieldAccessStats>> src,
            Func<string, bool> baseFilter = null)
        {
            if (dst == null || src == null)
                return;

            foreach (var baseKvp in src)
            {
                if (string.IsNullOrWhiteSpace(baseKvp.Key))
                    continue;
                if (baseFilter != null && !baseFilter(baseKvp.Key))
                    continue;

                if (!dst.TryGetValue(baseKvp.Key, out var byDispDst))
                    dst[baseKvp.Key] = byDispDst = new Dictionary<uint, FieldAccessStats>();

                foreach (var dispKvp in baseKvp.Value)
                {
                    if (!byDispDst.TryGetValue(dispKvp.Key, out var stDst))
                        byDispDst[dispKvp.Key] = stDst = new FieldAccessStats();

                    var stSrc = dispKvp.Value;
                    stDst.ReadCount += stSrc.ReadCount;
                    stDst.WriteCount += stSrc.WriteCount;
                    stDst.PointerUseCount += stSrc.PointerUseCount;

                    if (stSrc.IndexScaleCounts != null && stSrc.IndexScaleCounts.Count > 0)
                    {
                        foreach (var sc in stSrc.IndexScaleCounts)
                        {
                            stDst.IndexScaleCounts.TryGetValue(sc.Key, out var c);
                            stDst.IndexScaleCounts[sc.Key] = c + sc.Value;
                        }
                    }

                    if (stSrc.ArrayBoundCounts != null && stSrc.ArrayBoundCounts.Count > 0)
                    {
                        foreach (var bc in stSrc.ArrayBoundCounts)
                        {
                            stDst.ArrayBoundCounts.TryGetValue(bc.Key, out var c);
                            stDst.ArrayBoundCounts[bc.Key] = c + bc.Value;
                        }
                    }

                    if (string.IsNullOrEmpty(stDst.Size))
                    {
                        stDst.Size = stSrc.Size;
                    }
                    else if (!string.IsNullOrEmpty(stSrc.Size) && !string.Equals(stDst.Size, stSrc.Size, StringComparison.OrdinalIgnoreCase))
                    {
                        // Conflicting sizes across uses; leave blank to avoid misleading.
                        stDst.Size = string.Empty;
                    }
                }
            }
        }

        private static string FormatPointerStructTable(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            var ptrBases = statsByBase
                .Where(k => k.Key != null && k.Key.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                .Select(k => new
                {
                    Base = k.Key,
                    Total = k.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount),
                    Fields = k.Value
                })
                .Where(x => x.Total > 0)
                .OrderByDescending(x => x.Total)
                .ThenBy(x => x.Base)
                .Take(10)
                .ToList();

            if (ptrBases.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine(";");
            sb.AppendLine("; Inferred Pointer Struct Tables (best-effort, aggregated field access stats)");
            foreach (var b in ptrBases)
            {
                // Keep each struct compact: up to 10 fields, dropping +0 unless it looks important.
                var fields = b.Fields
                    .Where(k =>
                    {
                        if (k.Key != 0)
                            return true;
                        var st = k.Value;
                        if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                            return true;
                        var tot = st.ReadCount + st.WriteCount;
                        return string.IsNullOrEmpty(st.Size) && tot <= 8;
                    })
                    .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                    .ThenBy(k => k.Key)
                    .Take(10)
                    .Select(k =>
                    {
                        var disp = k.Key;
                        var st = k.Value;
                        var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                        var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                        var extra = FormatFieldExtraHints(st);
                        return $"+0x{disp:X}({rw}{sz}{extra})";
                    })
                    .ToList();

                if (fields.Count == 0)
                    continue;

                sb.AppendLine($"; STRUCT {b.Base}: {string.Join(", ", fields)}");
            }
            sb.AppendLine(";");
            return sb.ToString();
        }

        private static string FormatThisStructTable(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            var thisEntry = statsByBase.FirstOrDefault(k => string.Equals(k.Key, "this", StringComparison.OrdinalIgnoreCase));
            if (string.IsNullOrWhiteSpace(thisEntry.Key) || thisEntry.Value == null || thisEntry.Value.Count == 0)
                return string.Empty;

            var total = thisEntry.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount);
            if (total <= 0)
                return string.Empty;

            var fields = thisEntry.Value
                .Where(k =>
                {
                    if (k.Key != 0)
                        return true;
                    var st = k.Value;
                    if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                        return true;
                    var tot = st.ReadCount + st.WriteCount;
                    return string.IsNullOrEmpty(st.Size) && tot <= 8;
                })
                .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                .ThenBy(k => k.Key)
                .Take(12)
                .Select(k =>
                {
                    var disp = k.Key;
                    var st = k.Value;
                    var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                    var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                    var extra = FormatFieldExtraHints(st);
                    return $"+0x{disp:X}({rw}{sz}{extra})";
                })
                .ToList();

            if (fields.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine(";");
            sb.AppendLine("; Inferred 'this' Struct Table (best-effort, aggregated field access stats)");
            sb.AppendLine($"; STRUCT this: {string.Join(", ", fields)}");
            sb.AppendLine(";");
            return sb.ToString();
        }

        private static string RewriteFieldOperands(string insText, Dictionary<string, string> aliases)
        {
            if (string.IsNullOrEmpty(insText) || aliases == null || aliases.Count == 0)
                return insText;

            // Rewrite [reg+0xNN] -> [alias+field_NN] for aliases like this/arg0.
            return MemOpRegex.Replace(insText, m =>
            {
                var baseReg = m.Groups["base"].Value.ToLowerInvariant();
                if (baseReg == "esp" || baseReg == "ebp")
                    return m.Value;

                if (!aliases.TryGetValue(baseReg, out var a))
                {
                    if (baseReg == "ecx")
                        a = "this";
                    else
                        return m.Value;
                }

                var disp = 0u;
                if (m.Groups["disp"].Success)
                    disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);

                // Avoid rewriting huge displacements (often absolute addresses or jump tables already handled elsewhere).
                if (disp > 0x4000)
                    return m.Value;

                // Use field_0 for vptr-like deref.
                // For inferred pointer globals (ptr_XXXXXXXX), prefer addition form: [ptr_XXXXXXXX+field_0030]
                if (a.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                {
                    return disp == 0
                        ? $"[{a}+field_0000]"
                        : $"[{a}+field_{disp:X4}]";
                }

                return disp == 0
                    ? $"[{a}+field_0]"
                    : $"[{a}+field_{disp:X}]";
            });
        }

        private sealed class FpuStats
        {
            public int Total;
            public Dictionary<string, int> MnemonicCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public bool HasConvert;
            public bool HasCompare;
            public bool HasFld1;
            public bool HasFldz;
        }

        private static void CollectFpuOpsForFunction(List<Instruction> instructions, int startIdx, int endIdx, out FpuStats stats)
        {
            stats = new FpuStats();
            if (instructions == null || startIdx < 0 || endIdx > instructions.Count || startIdx >= endIdx)
                return;

            for (var i = startIdx; i < endIdx; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                var sp = t.IndexOf(' ');
                var mnemonic = (sp > 0 ? t.Substring(0, sp) : t).Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(mnemonic))
                    continue;

                // Best-effort: x87 mnemonics are typically 'f*' (fld/fstp/fmul/...)
                if (!mnemonic.StartsWith('f'))
                    continue;

                stats.Total++;
                stats.MnemonicCounts.TryGetValue(mnemonic, out var c);
                stats.MnemonicCounts[mnemonic] = c + 1;

                if (mnemonic.StartsWith("fild", StringComparison.OrdinalIgnoreCase) || mnemonic.StartsWith("fist", StringComparison.OrdinalIgnoreCase))
                    stats.HasConvert = true;
                if (mnemonic.StartsWith("fcom", StringComparison.OrdinalIgnoreCase) || mnemonic.StartsWith("fucom", StringComparison.OrdinalIgnoreCase))
                    stats.HasCompare = true;
                if (mnemonic.Equals("fld1", StringComparison.OrdinalIgnoreCase))
                    stats.HasFld1 = true;
                if (mnemonic.Equals("fldz", StringComparison.OrdinalIgnoreCase))
                    stats.HasFldz = true;
            }
        }

        private static string FormatFpuSummary(FpuStats stats)
        {
            if (stats == null || stats.Total < 4)
                return string.Empty;

            var top = stats.MnemonicCounts
                .OrderByDescending(k => k.Value)
                .ThenBy(k => k.Key)
                .Take(6)
                .Select(k => $"{k.Key}(x{k.Value})")
                .ToList();

            var tags = new List<string>();
            if (stats.HasConvert)
                tags.Add("convert");
            if (stats.HasCompare)
                tags.Add("compare/branch?");
            if (stats.HasFld1 || stats.HasFldz)
                tags.Add("constants");

            var tagText = tags.Count > 0 ? $" ; patterns: {string.Join(", ", tags)}" : string.Empty;
            return $"x87 ops={stats.Total}: {string.Join(", ", top)}{tagText}";
        }

        private static string TryAnnotateCriticalSectionIo(List<Instruction> instructions, int startIdx)
        {
            if (instructions == null || startIdx < 0 || startIdx >= instructions.Count)
                return string.Empty;

            // Critical sections can be fairly long (e.g., VGA register programming).
            // Keep it bounded, but large enough to catch typical cli..sti sequences.
            var cliSearchLimit = Math.Min(instructions.Count, startIdx + 64);
            var cliIdx = -1;
            var stiIdx = -1;

            for (var i = startIdx; i < cliSearchLimit; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.Equals("cli", StringComparison.OrdinalIgnoreCase))
                {
                    cliIdx = i;
                    break;
                }
            }

            if (cliIdx < 0)
                return string.Empty;

            var stiSearchLimit = Math.Min(instructions.Count, cliIdx + 256);
            for (var i = cliIdx + 1; i < stiSearchLimit; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.Equals("sti", StringComparison.OrdinalIgnoreCase))
                {
                    stiIdx = i;
                    break;
                }
            }

            if (stiIdx < 0)
                return string.Empty;

            ushort? lastDxImm16 = null;
            var ports = new Dictionary<ushort, IoPortStats>();

            for (var i = cliIdx + 1; i < stiIdx; i++)
            {
                var t = InsText(instructions[i]);
                if (TryParseMovDxImmediate(t, out var dxImm))
                    lastDxImm16 = dxImm;

                if (!TryParseIoAccess(t, lastDxImm16, out var port, out var isWrite, out var _))
                    continue;

                if (!ports.TryGetValue(port, out var st))
                    ports[port] = st = new IoPortStats();
                if (isWrite) st.Writes++; else st.Reads++;
            }

            if (ports.Count == 0)
                return string.Empty;

            var top = ports
                .OrderByDescending(p => p.Value.Reads + p.Value.Writes)
                .ThenBy(p => p.Key)
                .Take(4)
                .Select(p =>
                {
                    KnownIoPorts.TryGetValue(p.Key, out var name);
                    var rw = p.Value.Writes > 0 && p.Value.Reads > 0
                        ? $"r{p.Value.Reads}/w{p.Value.Writes}"
                        : (p.Value.Writes > 0 ? $"w{p.Value.Writes}" : $"r{p.Value.Reads}");
                    return !string.IsNullOrEmpty(name)
                        ? $"{name} (0x{p.Key:X4}) {rw}"
                        : $"0x{p.Key:X4} {rw}";
                })
                .ToList();

            return $"BBHINT: critical section (cli..sti) around I/O: {string.Join(", ", top)}";
        }

        private static bool TryParseCmpReg8Imm8(string insText, out string reg8, out byte imm8)
        {
            reg8 = null;
            imm8 = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples: "cmp al, 0x72" / "cmp al, 72h" / "cmp dl, 0"
            var m = Regex.Match(insText.Trim(), @"^cmp\s+(?<reg>[a-d][lh]|[sd]l|[sb]h)\s*,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg8 = m.Groups["reg"].Value.ToLowerInvariant();
            var tok = m.Groups["imm"].Value.Trim();

            if (!TryParseHexOrDecUInt32(tok, out var u) || u > 0xFF)
                return false;

            imm8 = (byte)u;
            return true;
        }

        private static bool IsEqualityJumpMnemonic(string insText)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = (sp > 0 ? t.Substring(0, sp) : t).Trim();

            return mnemonic.Equals("jz", StringComparison.OrdinalIgnoreCase)
                || mnemonic.Equals("je", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatImm8AsChar(byte b)
        {
            if (b >= 0x20 && b <= 0x7E)
            {
                var c = (char)b;
                if (c == '\\' || c == '\'' )
                    return $"'{c}'"; // keep it simple
                return $"'{c}'";
            }
            return string.Empty;
        }

        private static string ShortenInterruptHintForCase(string hint)
        {
            if (string.IsNullOrWhiteSpace(hint))
                return string.Empty;

            var t = hint.Trim();
            if (t.StartsWith("INT21: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT21: ".Length);
            else if (t.StartsWith("INT31: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT31: ".Length);
            else if (t.StartsWith("INT: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT: ".Length);

            if (t.StartsWith("DOS API:", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("DOS API:".Length).Trim();

            // Drop extra pointer details.
            var semi = t.IndexOf(';');
            if (semi >= 0)
                t = t.Substring(0, semi).Trim();

            // Keep it compact.
            if (t.Length > 42)
                t = t.Substring(0, 42) + "...";

            return t;
        }

        private static string ShortenIoHintForCase(string hint)
        {
            if (string.IsNullOrWhiteSpace(hint))
                return string.Empty;

            var t = hint.Trim();
            if (t.StartsWith("IO: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("IO: ".Length);

            var paren = t.IndexOf('(');
            if (paren >= 0)
                t = t.Substring(0, paren).Trim();

            if (t.Length > 42)
                t = t.Substring(0, 42) + "...";

            return t;
        }
    }
}
