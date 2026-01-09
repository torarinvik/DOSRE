using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Analysis;
using DOSRE.Enums;
using DOSRE.Logging;
using NLog;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    /// Minimal disassembler for DOS4GW Linear Executable (LE) format.
    ///
    /// This is intentionally "minimal" compared to the NE pipeline:
    /// - No relocation/fixup processing
    /// - No import/entry table analysis
    /// - No NE-specific analysis
    /// - No string scanning
    ///
    /// It reconstructs object bytes from LE pages and disassembles executable objects as x86_32.
    /// </summary>
    public static partial class LEDisassembler
    {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));

        private const ushort LE_OBJECT_ENTRY_SIZE = 24;

        private sealed class FunctionSummary
        {
            public uint Start;
            public int InstructionCount;
            public int BlockCount;
            public readonly HashSet<uint> Calls = new HashSet<uint>();
            public readonly HashSet<string> Globals = new HashSet<string>(StringComparer.Ordinal);
            public readonly HashSet<string> Strings = new HashSet<string>(StringComparer.Ordinal);

            public string ToComment()
            {
                var calls = Calls.Count > 0 ? string.Join(", ", Calls.OrderBy(x => x).Take(12).Select(x => $"func_{x:X8}")) : "(none)";
                var globs = Globals.Count > 0 ? string.Join(", ", Globals.OrderBy(x => x).Take(12)) : "(none)";
                var strs = Strings.Count > 0 ? string.Join(", ", Strings.OrderBy(x => x).Take(12)) : "(none)";
                return $"; SUMMARY: ins={InstructionCount} blocks={BlockCount} calls={calls} globals={globs} strings={strs}";
            }
        }

        private static readonly Regex EbpDispRegex = new Regex(
            "\\[(?<reg>ebp)\\s*(?<sign>[\\+\\-])\\s*(?<hex>0x[0-9A-Fa-f]+)\\]",
            RegexOptions.Compiled);
        private static readonly Regex StringSymRegex = new Regex("s_[0-9A-Fa-f]{8}", RegexOptions.Compiled);
        private static readonly Regex ResourceSymRegex = new Regex("r_[0-9A-Fa-f]{8}", RegexOptions.Compiled);

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
                    var t = insList[j].ToString().Trim();
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
                var insText = instructions[i].ToString().Trim();

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
                // For inferred pointer globals (ptr_XXXXXXXX), prefer dotted form: [ptr_XXXXXXXX.field_0030]
                if (a.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                {
                    return disp == 0
                        ? $"[{a}.field_0000]"
                        : $"[{a}.field_{disp:X4}]";
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
                var t = instructions[i].ToString().Trim();
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
                var t = instructions[i].ToString().Trim();
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
                var t = instructions[i].ToString().Trim();
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
                var t = instructions[i].ToString();
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
            HashSet<uint> blockStarts,
            uint startAddr,
            uint endAddrExclusive,
            int startIdx,
            int endIdxExclusive,
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

                if (!TryGetRelativeBranchTarget(ins, out var target, out var isCall) || isCall)
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
                if (blockStarts == null || blockStarts.Count == 0)
                    return endAddrExclusive;
                var next = blockStarts.Where(b => b > blockStart && b < endAddrExclusive).OrderBy(b => b).FirstOrDefault();
                return next == 0 ? endAddrExclusive : next;
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
                    var cooked = RewriteStackFrameOperands(instructions[i].ToString()).Trim();
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
                        var t = RewriteStackFrameOperands(instructions[j].ToString()).Trim();
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
                            var cooked = RewriteStackFrameOperands(instructions[i].ToString()).Trim();

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

                        var latchText = RewriteStackFrameOperands(instructions[latchIdx].ToString()).Trim();
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
                                    var prev = RewriteStackFrameOperands(instructions[k].ToString()).Trim();
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
                                        var prev = RewriteStackFrameOperands(instructions[k].ToString()).Trim();

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
                                var prev = RewriteStackFrameOperands(instructions[k].ToString()).Trim();

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
                var cooked = RewriteStackFrameOperands(instructions[i].ToString()).Trim();

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
                var t = instructions[i].ToString().Trim();
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
                var raw = instructions[i].ToString();
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

        private static string TryAnnotateByteSwitchDecisionTree(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int startIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out string signature,
            out Dictionary<string, string> inferredLocalAliases,
            out List<string> localAliasHints)
        {
            // Recognize compiler-generated decision trees for switch/case on a byte register.
            // Typical shape: cmp al, imm ; jz loc_case ; ... ; unconditional jmp loc_default
            signature = null;
            inferredLocalAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            localAliasHints = new List<string>();
            if (instructions == null || startIdx < 0 || startIdx >= instructions.Count)
                return string.Empty;

            // Guard: only annotate at decision-tree nodes that actually start with the canonical compare.
            if (!TryParseCmpReg8Imm8(instructions[startIdx].ToString(), out _, out _))
                return string.Empty;

            // First, try to stabilize the "chain start" by scanning backwards for nearby cmp+je patterns.
            // This keeps the signature consistent even if we emit at bb_ labels mid-chain.
            const int backWindow = 256;
            const int forwardWindow = 256;

            var backLimit = Math.Max(0, startIdx - backWindow);
            var chainStart = startIdx;
            string chainReg = null;
            for (var i = startIdx; i >= backLimit; i--)
            {
                if (i + 1 >= instructions.Count)
                    continue;

                var a = instructions[i].ToString();
                if (!TryParseCmpReg8Imm8(a, out var r8, out _))
                    continue;

                if (!IsEqualityJumpMnemonic(instructions[i + 1].ToString()))
                    continue;

                if (chainReg == null)
                    chainReg = r8;
                else if (!chainReg.Equals(r8, StringComparison.OrdinalIgnoreCase))
                    continue;

                chainStart = i;
            }

            var maxScan = Math.Min(instructions.Count, chainStart + forwardWindow);

            // Collect equality tests for a single reg8.
            var reg = chainReg;
            var cases = new Dictionary<byte, uint>();

            for (var i = chainStart; i + 1 < maxScan; i++)
            {
                var a = instructions[i].ToString();
                if (!TryParseCmpReg8Imm8(a, out var r8, out var imm8))
                    continue;

                if (reg == null)
                    reg = r8;
                else if (!reg.Equals(r8, StringComparison.OrdinalIgnoreCase))
                    continue;

                var b = instructions[i + 1];
                if (!IsEqualityJumpMnemonic(b.ToString()))
                    continue;

                if (TryGetRelativeBranchTarget(b, out var target, out var isCall) && !isCall)
                {
                    if (!cases.ContainsKey(imm8))
                        cases[imm8] = (uint)target;
                }
            }

            if (string.IsNullOrEmpty(reg) || cases.Count < 4)
                return string.Empty;

            signature = reg + "|" + string.Join(",", cases.OrderBy(k => k.Key).Select(k => $"{k.Key:X2}->{k.Value:X8}"));

            // Best-effort interpretation: if this is predominantly printable ASCII cases, it's probably token/command dispatch.
            var printable = cases.Keys.Count(b => b >= 0x20 && b <= 0x7E);
            var maybeAsciiDispatch = printable >= 4 && (printable * 1.0 / cases.Count) >= 0.75;
            var maybeTokenChar = maybeAsciiDispatch && cases.Keys.Any(b => b == 0x20 || b == (byte)'-' || b == (byte)'/' || b == (byte)'.' || b == (byte)'_');
            var kind = maybeTokenChar
                ? "ASCII dispatch (likely token/command char)"
                : (maybeAsciiDispatch ? "ASCII dispatch" : string.Empty);

            // Compute per-case roles first, then infer local aliases, then render using the aliases.
            var roleByCase = new Dictionary<byte, string>();
            foreach (var kv in cases)
            {
                var role = TrySummarizeCaseTargetRole(instructions, insIndexByAddr, kv.Value, stringSymbols, stringPreview, objects, objBytesByIndex);
                if (!string.IsNullOrEmpty(role))
                    roleByCase[kv.Key] = role;
            }

            InferLocalAliasesFromSwitchCases(roleByCase, out inferredLocalAliases, out localAliasHints);

            // Don't capture the out-parameter in lambdas.
            var inferredAliases = inferredLocalAliases;

            var parts = cases
                .OrderBy(k => k.Key)
                .Take(10)
                .Select(k =>
                {
                    var ch = FormatImm8AsChar(k.Key);
                    var imm = !string.IsNullOrEmpty(ch) ? $"{ch} (0x{k.Key:X2})" : $"0x{k.Key:X2}";
                    roleByCase.TryGetValue(k.Key, out var role);
                    if (!string.IsNullOrEmpty(role))
                    {
                        role = RewriteLocalAliasTokens(role, inferredAliases);
                        return $"{imm}->loc_{k.Value:X8} ({role})";
                    }
                    return $"{imm}->loc_{k.Value:X8}";
                })
                .ToList();

            var more = cases.Count > 10 ? $", ... (+{cases.Count - 10})" : string.Empty;
            var kindSuffix = string.IsNullOrEmpty(kind) ? string.Empty : $" {kind}:";
            return $"BBHINT: switch({reg}) decision tree{kindSuffix} {string.Join(", ", parts)}{more}";
        }

        private static string RewriteStackFrameOperands(string insText)
        {
            if (string.IsNullOrEmpty(insText))
                return insText;

            // Best-effort: rewrite [ebp +/- 0xNN] to [arg_N]/[local_NN]
            // Assumes typical 32-bit stack frame: [ebp+8] is arg0.
            return EbpDispRegex.Replace(insText, m =>
            {
                var sign = m.Groups["sign"].Value;
                var hex = m.Groups["hex"].Value;
                if (!TryParseHexUInt(hex, out var off))
                    return m.Value;

                if (sign == "-")
                {
                    // locals grow downward
                    return $"[local_{off:X}]";
                }

                // args: ebp+8 is first arg
                if (off >= 8 && (off - 8) % 4 == 0)
                {
                    var argIndex = (off - 8) / 4;
                    return $"[arg_{argIndex}]";
                }

                return m.Value;
            });
        }

        private static string RewriteLocalAliasTokens(string text, Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrEmpty(text) || localAliases == null || localAliases.Count == 0)
                return text;

            return Regex.Replace(text, @"\blocal_[0-9A-Fa-f]+\b", m =>
            {
                var key = m.Value;
                if (localAliases.TryGetValue(key, out var alias) && !string.IsNullOrWhiteSpace(alias))
                    return alias;
                return key;
            });
        }

        private sealed class LocalAliasEvidence
        {
            public readonly HashSet<byte> Cases = new HashSet<byte>();
            public readonly HashSet<uint> Values = new HashSet<uint>();
            public bool AddressTaken;
        }

        private static bool TryParseRoleNoteSetLocal(string note, out string localName, out uint value)
        {
            localName = null;
            value = 0;
            if (string.IsNullOrWhiteSpace(note))
                return false;

            // Example: "set local_1C=0x1"
            var m = Regex.Match(note.Trim(), @"^set\s+(?<local>local_[0-9A-Fa-f]+)\s*=\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            localName = m.Groups["local"].Value;
            var imm = m.Groups["imm"].Value;
            if (!TryParseHexOrDecUInt32(imm, out var v))
                return false;
            value = v;
            return true;
        }

        private static bool TryParseRoleNoteAddrTaken(string note, out string localName)
        {
            localName = null;
            if (string.IsNullOrWhiteSpace(note))
                return false;

            // Example: "edx=&local_14"
            var m = Regex.Match(note.Trim(), @"^(?<reg>e[a-z]{2})\s*=\s*&(?<local>local_[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            localName = m.Groups["local"].Value;
            return true;
        }

        private static bool IsSafeAliasIdent(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return false;
            return Regex.IsMatch(s, @"^[A-Za-z_][A-Za-z0-9_]*$");
        }

        private static string MakeOutpAliasFromLocal(string localName)
        {
            if (string.IsNullOrWhiteSpace(localName))
                return null;

            // local_14 -> outp_14
            var m = Regex.Match(localName, @"^local_(?<hex>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return null;

            return "outp_" + m.Groups["hex"].Value.ToUpperInvariant();
        }

        private static bool TryParseLeaRegOfLocal(string insText, out string reg, out string localName)
        {
            reg = null;
            localName = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Example: "lea edx, [local_14]"
            var m = Regex.Match(insText.Trim(), @"^lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<mem>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            localName = m.Groups["mem"].Value;
            return true;
        }

        private static bool TryParsePushReg(string insText, out string reg)
        {
            reg = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;
            var m = Regex.Match(insText.Trim(), @"^push\s+(?<reg>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;
            reg = m.Groups["reg"].Value.ToLowerInvariant();
            return true;
        }

        private static bool InstructionWritesReg(string insText, string reg)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // Reuse existing coarse matcher.
            var m = WritesRegRegex.Match(insText.Trim());
            if (!m.Success)
                return false;
            return m.Groups["dst"].Value.Equals(reg, StringComparison.OrdinalIgnoreCase);
        }

        private static int? GetRegBitWidth(string reg)
        {
            if (string.IsNullOrWhiteSpace(reg))
                return null;

            reg = reg.Trim().ToLowerInvariant();
            if (reg.Length == 3 && reg[0] == 'e')
                return 32;

            // 16-bit
            if (reg is "ax" or "bx" or "cx" or "dx" or "si" or "di" or "bp" or "sp")
                return 16;

            // 8-bit
            if (reg is "al" or "ah" or "bl" or "bh" or "cl" or "ch" or "dl" or "dh")
                return 8;

            return null;
        }

        private static void MergeBitWidthHint(Dictionary<string, int> bitsByToken, string token, int bits)
        {
            if (bitsByToken == null || string.IsNullOrWhiteSpace(token) || bits <= 0)
                return;

            if (bitsByToken.TryGetValue(token, out var prev))
                bitsByToken[token] = Math.Max(prev, bits);
            else
                bitsByToken[token] = bits;
        }

        private static void CollectLocalBitWidthHintsForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, int> bitsByLocal)
        {
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(instructions[i].ToString());
                var t = cooked.Trim();

                // mov [local_XX], reg
                var m = Regex.Match(t, @"^mov\s+\[(?<local>local_[0-9A-Fa-f]+)\]\s*,\s*(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\b", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // mov reg, [local_XX]
                m = Regex.Match(t, @"^mov\s+(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\s*,\s*\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // explicit-sized mem ops (byte/word/dword/qword/tword)
                m = Regex.Match(t, @"\b(?<sz>byte|word|dword|qword|tword)\s+\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var sz = m.Groups["sz"].Value.ToLowerInvariant();
                    var bits = sz switch
                    {
                        "byte" => 8,
                        "word" => 16,
                        "dword" => 32,
                        "qword" => 64,
                        "tword" => 80,
                        _ => 0
                    };
                    if (bits > 0)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits);
                    continue;
                }
            }
        }

        private static string UpgradeOutpAliasWithBitWidth(string alias, int bits)
        {
            if (string.IsNullOrWhiteSpace(alias))
                return alias;

            // outp_14 -> outp16_14, etc.
            var m = Regex.Match(alias, @"^outp_(?<hex>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return alias;

            var suffix = m.Groups["hex"].Value.ToUpperInvariant();
            return bits switch
            {
                8 => $"outp8_{suffix}",
                16 => $"outp16_{suffix}",
                32 => $"outp32_{suffix}",
                64 => $"outp64_{suffix}",
                80 => $"outp80_{suffix}",
                _ => alias
            };
        }

        private static string FormatProtoArgs(int argCount, int maxArgs)
        {
            if (argCount <= 0)
                return string.Empty;
            if (maxArgs <= 0)
                maxArgs = 12;

            var shown = Math.Min(argCount, maxArgs);
            var args = string.Join(", ", Enumerable.Range(0, shown).Select(x => $"arg_{x}"));
            if (shown < argCount)
                args += $", ... (+{argCount - shown})";
            return args;
        }

        private static bool TryParseMovRegFromTokenMem(string insText, out string reg, out string token)
        {
            reg = null;
            token = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples: "mov eax, [arg_0]", "mov edx, [local_20]"
            var m = Regex.Match(insText.Trim(), @"^mov\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            token = m.Groups["tok"].Value;
            return true;
        }

        private static bool InsTextUsesRegAsMemBase(string insText, string reg)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // Any memory operand like [reg] or [reg+...] etc.
            return Regex.IsMatch(insText, $@"\[(?:[^\]]*\b{Regex.Escape(reg)}\b[^\]]*)\]", RegexOptions.IgnoreCase);
        }

        private static bool LooksLikeFunctionFrameSetup(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            var t = instructions[idx].ToString().Trim();

            // Classic: push ebp; mov ebp, esp
            if (t.Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase))
            {
                var back = Math.Max(0, idx - 4);
                for (var i = back; i < idx; i++)
                {
                    if (instructions[i].ToString().Trim().Equals("push ebp", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            // Less common, but still a clear frame setup.
            if (t.StartsWith("enter ", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static void InferPointerishTokensForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out HashSet<string> pointerTokens)
        {
            pointerTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Tracks reg <- [arg/local], and marks that source as pointer-ish if the reg is later used as a memory base.
            var regSource = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(instructions[i].ToString());

                // Far-pointer loads imply the argument/local represents a pointer value (ES:reg etc).
                // Examples: "les edi, [arg_1]", "lgs eax, [arg_3]".
                var fp = Regex.Match(cooked.Trim(), @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\b", RegexOptions.IgnoreCase);
                if (fp.Success)
                    pointerTokens.Add(fp.Groups["tok"].Value);

                if (TryParseMovRegFromTokenMem(cooked, out var dstReg, out var tok))
                    regSource[dstReg] = tok;

                foreach (var kv in regSource.ToList())
                {
                    var reg = kv.Key;
                    var src = kv.Value;

                    if (InsTextUsesRegAsMemBase(cooked, reg))
                        pointerTokens.Add(src);

                    if (InstructionWritesReg(cooked, reg))
                        regSource.Remove(reg);
                }
            }
        }

        private static string RewriteArgAliasTokens(string text, Dictionary<string, string> argAliases)
        {
            if (string.IsNullOrEmpty(text) || argAliases == null || argAliases.Count == 0)
                return text;

            return Regex.Replace(text, @"\barg_[0-9]+\b", m =>
            {
                var key = m.Value;
                if (argAliases.TryGetValue(key, out var alias) && !string.IsNullOrWhiteSpace(alias))
                    return alias;
                return key;
            }, RegexOptions.IgnoreCase);
        }

        private static void ApplyPointerAliasForToken(string token, Dictionary<string, string> argAliases, Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrWhiteSpace(token))
                return;

            if (token.StartsWith("arg_", StringComparison.OrdinalIgnoreCase))
            {
                if (argAliases != null && !argAliases.ContainsKey(token))
                    argAliases[token] = "ptr_" + token;
                return;
            }

            if (token.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
            {
                if (localAliases == null)
                    return;

                if (localAliases.TryGetValue(token, out var existing) && !string.IsNullOrWhiteSpace(existing))
                {
                    if (!existing.StartsWith("opt_", StringComparison.OrdinalIgnoreCase) && !existing.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                        localAliases[token] = "ptr_" + existing;
                }
                else
                {
                    localAliases[token] = "ptr_" + token;
                }
            }
        }

        private static void UpdatePointerishTokenAliases(
            string insText,
            Dictionary<string, string> regSources,
            Dictionary<string, string> argAliases,
            Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return;

            // Far-pointer loads imply the operand token represents a pointer value.
            var fp = Regex.Match(insText.Trim(), @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (fp.Success)
                ApplyPointerAliasForToken(fp.Groups["tok"].Value, argAliases, localAliases);

            // Track reg <- &arg/local
            var lea = Regex.Match(insText.Trim(), @"^lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (lea.Success)
                regSources[lea.Groups["reg"].Value.ToLowerInvariant()] = lea.Groups["tok"].Value;

            // Track reg <- [arg/local]
            if (TryParseMovRegFromTokenMem(insText, out var dstReg, out var tok))
                regSources[dstReg] = tok;

            // If a tracked reg is used as a memory base, mark its source token pointer-ish.
            foreach (var kv in regSources.ToList())
            {
                var reg = kv.Key;
                var src = kv.Value;
                if (InsTextUsesRegAsMemBase(insText, reg))
                    ApplyPointerAliasForToken(src, argAliases, localAliases);

                if (InstructionWritesReg(insText, reg))
                    regSources.Remove(reg);
            }
        }

        private static void InferOutParamLocalAliasesForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Track most recent address-taken locals per register.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var raw = instructions[i].ToString();
                var cooked = RewriteStackFrameOperands(raw);

                if (TryParseLeaRegOfLocal(cooked, out var leaReg, out var localName))
                {
                    lastLeaLocalByReg[leaReg] = (localName, i);
                    continue;
                }

                // Invalidate reg->local if the reg is overwritten.
                foreach (var k in lastLeaLocalByReg.Keys.ToList())
                {
                    if (InstructionWritesReg(cooked, k))
                        lastLeaLocalByReg.Remove(k);
                }

                var t = cooked.TrimStart();
                if (!t.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Heuristic: if we have a recent lea reg,[local] and either:
                // - the reg was pushed as an arg, or
                // - the lea is close enough to the call and reg wasn't overwritten
                // then the local is likely an out-parameter / by-ref temp.

                var pushedRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var back = Math.Max(startIdx, i - 10);
                for (var j = back; j < i; j++)
                {
                    var prev = RewriteStackFrameOperands(instructions[j].ToString());
                    if (TryParsePushReg(prev, out var pr))
                        pushedRegs.Add(pr);
                }

                foreach (var kv in lastLeaLocalByReg.ToList())
                {
                    var reg = kv.Key;
                    var (loc, leaIdx) = kv.Value;

                    if ((i - leaIdx) > 8)
                        continue;

                    var isPushedArg = pushedRegs.Contains(reg);
                    var isImmediateRegArg = (i - leaIdx) == 1;

                    // Push-required renaming: only rewrite locals when we see the address actually passed on stack.
                    // Still emit a low-confidence hint for lea+call adjacency.
                    if (!isPushedArg && !isImmediateRegArg)
                        continue;

                    if (!isPushedArg)
                    {
                        if (hintedLocals.Add(loc))
                            aliasHints.Add($"VARHINT: {loc} maybe outparam (lea {reg}, [{loc}] immediately before call)");
                        continue;
                    }

                    if (inferredAliases.ContainsKey(loc))
                        continue;

                    var alias = MakeOutpAliasFromLocal(loc);
                    if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                        continue;

                    inferredAliases[loc] = alias;
                    aliasHints.Add($"VARALIAS: {loc} -> {alias} (outparam; inferred from push+call)");
                }
            }
        }

        private static void InferArgsAndCallingConventionForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out int argCount,
            out string cc,
            out int? retImmBytes)
        {
            argCount = 0;
            cc = null;
            retImmBytes = null;

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(instructions.Count, endIdx);
            var usedArgMax = -1;
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(instructions[i].ToString());
                foreach (Match m in Regex.Matches(cooked, @"\barg_(?<idx>[0-9]+)\b", RegexOptions.IgnoreCase))
                {
                    if (int.TryParse(m.Groups["idx"].Value, out var idx))
                        usedArgMax = Math.Max(usedArgMax, idx);
                }
            }

            // Find the last ret in the function range.
            for (var i = max - 1; i >= startIdx; i--)
            {
                var t = instructions[i].ToString().Trim();
                if (!t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    continue;

                var m = Regex.Match(t, @"^ret\s+(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                if (m.Success && TryParseHexOrDecUInt32(m.Groups["imm"].Value, out var imm))
                    retImmBytes = (int)imm;
                break;
            }

            if (retImmBytes.HasValue && retImmBytes.Value > 0)
            {
                cc = "stdcall";
                if (retImmBytes.Value % 4 == 0)
                    argCount = Math.Max(argCount, retImmBytes.Value / 4);
            }
            else
            {
                cc = "cdecl";
            }

            if (usedArgMax >= 0)
                argCount = Math.Max(argCount, usedArgMax + 1);
        }

        private static string MakeOptAliasFromCase(byte caseVal)
        {
            if (caseVal >= (byte)'A' && caseVal <= (byte)'Z')
                return $"opt_{(char)caseVal}";
            if (caseVal >= (byte)'a' && caseVal <= (byte)'z')
                return $"opt_{(char)caseVal}";
            if (caseVal >= (byte)'0' && caseVal <= (byte)'9')
                return $"opt_{(char)caseVal}";
            return $"opt_0x{caseVal:X2}";
        }

        private static string MakeOutAliasFromCase(byte caseVal)
        {
            if (caseVal >= (byte)'A' && caseVal <= (byte)'Z')
                return $"out_{(char)caseVal}";
            if (caseVal >= (byte)'a' && caseVal <= (byte)'z')
                return $"out_{(char)caseVal}";
            if (caseVal >= (byte)'0' && caseVal <= (byte)'9')
                return $"out_{(char)caseVal}";
            return $"out_0x{caseVal:X2}";
        }

        private static void InferLocalAliasesFromSwitchCases(
            Dictionary<byte, string> roleByCase,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (roleByCase == null || roleByCase.Count == 0)
                return;

            var evidence = new Dictionary<string, LocalAliasEvidence>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in roleByCase)
            {
                var caseVal = kv.Key;
                var role = kv.Value;
                if (string.IsNullOrWhiteSpace(role))
                    continue;

                foreach (var part in role.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (TryParseRoleNoteSetLocal(part, out var local, out var v))
                    {
                        if (!evidence.TryGetValue(local, out var ev))
                            evidence[local] = ev = new LocalA