using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Analysis;
using DOSRE.Logging;
using NLog;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    /// <summary>
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
    public static class LEDisassembler
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
        private static readonly Regex MemOpWithSizeRegex = new Regex(
            @"(?<size>byte|word|dword)\s+\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private sealed class FieldAccessStats
        {
            public int ReadCount;
            public int WriteCount;
            public string Size = string.Empty;
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

        private static void UpdatePointerAliases(string insText, Dictionary<string, string> aliases)
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

            if (readInc > 0)
                st.ReadCount += readInc;
            if (writeInc > 0)
                st.WriteCount += writeInc;
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

            // Read-modify-write when memory is destination.
            switch (mnemonic)
            {
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
                case "push":
                case "call":
                    reads = 1;
                    return;
            }

            // FP memory ops: fstp writes; fld reads. Others default to read.
            if (mnemonic.StartsWith("fst", StringComparison.OrdinalIgnoreCase))
            {
                writes = 1;
                return;
            }
            if (mnemonic.StartsWith("fld", StringComparison.OrdinalIgnoreCase))
            {
                reads = 1;
                return;
            }

            // Default: assume read.
            reads = 1;
        }

        private static void CollectFieldAccessesForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive,
            out Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            statsByBase = new Dictionary<string, Dictionary<uint, FieldAccessStats>>(StringComparer.Ordinal);
            if (instructions == null || startIdx < 0 || endIdxExclusive > instructions.Count || startIdx >= endIdxExclusive)
                return;

            // Track pointer-ish aliases: ecx is likely this.
            var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ecx"] = "this"
            };

            for (var i = startIdx; i < endIdxExclusive; i++)
            {
                var insText = instructions[i].ToString().Trim();

                // Update aliases first so we model dataflow forward.
                UpdatePointerAliases(insText, aliases);

                // Prefer size when present (byte/word/dword).
                var size = string.Empty;
                var ms = MemOpWithSizeRegex.Match(insText);
                if (ms.Success)
                    size = ms.Groups["size"].Value.ToLowerInvariant();

                foreach (Match m in MemOpRegex.Matches(insText))
                {
                    var baseReg = m.Groups["base"].Value.ToLowerInvariant();
                    if (baseReg == "esp" || baseReg == "ebp")
                        continue;

                    if (!aliases.TryGetValue(baseReg, out var baseAlias))
                    {
                        if (baseReg == "ecx")
                            baseAlias = "this";
                        else
                            continue;
                    }

                    var disp = 0u;
                    if (m.Groups["disp"].Success)
                        disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);

                    // Best-effort per-operand read/write classification.
                    var memText = m.Value; // e.g. [ecx+0x10]
                    GetMemAccessRW(insText, memText, out var r, out var w);
                    RecordFieldAccess(statsByBase, baseAlias, disp, r, w, size);
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
                        return $"+0x{disp:X}({rw}{sz})";
                    });
                parts.Add($"{baseAlias}: {string.Join(", ", fields)}");
            }

            if (parts.Count == 0)
                return string.Empty;
            return $"FIELDS: {string.Join(" | ", parts)}";
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
                return disp == 0
                    ? $"[{a}+field_0]"
                    : $"[{a}+field_{disp:X}]";
            });
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

        private static void ScanStrings(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, out Dictionary<uint, string> symbols, out Dictionary<uint, string> preview)
        {
            symbols = new Dictionary<uint, string>();
            preview = new Dictionary<uint, string>();

            if (objects == null || objBytesByIndex == null)
                return;

            // Very lightweight string scan: runs of printable bytes terminated by 0.
            // To reduce noise, prefer scanning non-executable objects (data-ish).
            foreach (var obj in objects)
            {
                var isExecutable = (obj.Flags & 0x0004) != 0;
                if (isExecutable)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes) || bytes == null || bytes.Length == 0)
                    continue;

                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)bytes.Length);
                var i = 0;
                while (i < maxLen)
                {
                    // Find start of a printable run.
                    if (!IsLikelyStringChar(bytes[i]))
                    {
                        i++;
                        continue;
                    }

                    var start = i;
                    var sb = new StringBuilder();
                    while (i < maxLen && IsLikelyStringChar(bytes[i]) && sb.Length < 200)
                    {
                        sb.Append((char)bytes[i]);
                        i++;
                    }

                    // Require NUL terminator nearby to avoid random data.
                    var nul = (i < maxLen && bytes[i] == 0x00);
                    var s = sb.ToString();
                    if (nul && s.Length >= 4 && LooksLikeHumanString(s))
                    {
                        var linear = obj.BaseAddress + (uint)start;
                        if (!symbols.ContainsKey(linear))
                        {
                            symbols[linear] = $"s_{linear:X8}";
                            preview[linear] = EscapeForComment(s);
                        }
                    }

                    // Skip the terminator if present.
                    if (nul)
                        i++;
                }
            }
        }

        private static bool LooksLikeHumanString(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4)
                return false;

            var letters = 0;
            var digits = 0;
            var spaces = 0;
            var punctuation = 0;

            foreach (var ch in s)
            {
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
                    letters++;
                else if (ch >= '0' && ch <= '9')
                    digits++;
                else if (ch == ' ')
                    spaces++;
                else if (".,:;!?/\\-_()[]{}'\"".IndexOf(ch) >= 0)
                    punctuation++;
            }

            // Require at least some real “text signal”.
            if (letters < 2)
                return false;

            // Avoid things that are almost all hex-ish or symbols.
            if (letters + digits + spaces + punctuation == 0)
                return false;

            // Prefer either spaces or common punctuation or longer strings.
            return spaces > 0 || punctuation > 0 || s.Length >= 10;
        }

        private static bool IsLikelyStringChar(byte b)
        {
            // Accept basic printable ASCII plus a few common CP437 punctuation bytes.
            if (b >= 0x20 && b <= 0x7E)
                return true;
            // Tab
            if (b == 0x09)
                return true;
            return false;
        }

        private static string EscapeForComment(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;

            // Keep comments readable
            s = s.Replace("\\r", " ").Replace("\\n", " ").Replace("\t", " ");
            if (s.Length > 120)
                s = s.Substring(0, 120) + "...";
            return s;
        }

        private static string ApplyStringSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> stringSymbols, List<LEObject> objects = null)
        {
            if (stringSymbols == null || stringSymbols.Count == 0 || fixupsHere == null || fixupsHere.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!f.Value32.HasValue)
                    continue;

                var raw = f.Value32.Value;
                string sym = null;

                // Common case: raw already equals a linear string address.
                if (!stringSymbols.TryGetValue(raw, out sym))
                {
                    // Common DOS4GW pattern: raw is a small offset into a fixed resource region.
                    // If base+raw matches a known string symbol, rewrite the raw immediate to that symbol.
                    if (raw < 0x10000)
                    {
                        foreach (var baseAddr in new[] { 0x000C0000u, 0x000D0000u, 0x000E0000u, 0x000F0000u })
                        {
                            var linear = unchecked(baseAddr + raw);
                            if (stringSymbols.TryGetValue(linear, out sym))
                                break;
                        }
                    }

                    // Fallback: sometimes raw is object-relative and the fixup mapping tells us the true target.
                    if (objects != null && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                    {
                        var objIndex = f.TargetObject.Value;
                        if (objIndex >= 1 && objIndex <= objects.Count)
                        {
                            var linear = unchecked(objects[objIndex - 1].BaseAddress + f.TargetOffset.Value);
                            stringSymbols.TryGetValue(linear, out sym);
                        }
                    }
                }

                if (string.IsNullOrEmpty(sym))
                    continue;

                var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                if (!TryClassifyFixupKind(ins, delta, out var kind))
                    continue;

                // Strings typically appear as imm32 addresses (push/mov) but can be disp32 too.
                if (kind != "imm32" && kind != "imm32?" && kind != "disp32")
                    continue;

                var needleLower = $"0x{raw:x}";
                var needleUpper = $"0x{raw:X}";
                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }

        private static void BuildBasicBlocks(List<Instruction> instructions, uint startLinear, uint endLinear, HashSet<uint> functionStarts, HashSet<uint> labelTargets,
            out HashSet<uint> blockStarts, out Dictionary<uint, List<uint>> blockPreds)
        {
            blockStarts = new HashSet<uint>();
            blockPreds = new Dictionary<uint, List<uint>>();

            if (instructions == null || instructions.Count == 0)
                return;

            foreach (var f in functionStarts)
                blockStarts.Add(f);
            foreach (var t in labelTargets)
                blockStarts.Add(t);

            // Add fallthrough starts after conditional branches.
            for (var i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;
                var nextAddr = addr + (uint)ins.Length;

                if (TryGetRelativeBranchTarget(ins, out var target, out var isCall))
                {
                    if (!isCall)
                    {
                        // Branch target is already a block start via labelTargets.
                        if (nextAddr >= startLinear && nextAddr < endLinear && IsConditionalBranch(ins))
                            blockStarts.Add(nextAddr);

                        // Precompute preds
                        AddPred(blockPreds, target, addr);
                        if (IsConditionalBranch(ins))
                            AddPred(blockPreds, nextAddr, addr);
                    }
                }
            }
        }

        private static void AddPred(Dictionary<uint, List<uint>> preds, uint dst, uint src)
        {
            if (!preds.TryGetValue(dst, out var list))
                preds[dst] = list = new List<uint>();
            list.Add(src);
        }

        private static bool IsConditionalBranch(Instruction ins)
        {
            if (ins == null)
                return false;
            // Cheap heuristic based on mnemonic text
            var s = ins.ToString();
            return s.StartsWith("j", StringComparison.OrdinalIgnoreCase) &&
                   !s.StartsWith("jmp", StringComparison.OrdinalIgnoreCase);
        }

        private static Dictionary<uint, FunctionSummary> SummarizeFunctions(List<Instruction> instructions, HashSet<uint> functionStarts, HashSet<uint> blockStarts, List<LEFixup> sortedFixups,
            Dictionary<uint, string> globalSymbols, Dictionary<uint, string> stringSymbols)
        {
            var summaries = new Dictionary<uint, FunctionSummary>();
            if (instructions == null || instructions.Count == 0 || functionStarts == null || functionStarts.Count == 0)
                return summaries;

            // Sort function starts by address and use next start as boundary.
            var starts = functionStarts.OrderBy(x => x).ToList();
            var insByAddr = instructions.ToDictionary(i => (uint)i.Offset, i => i);

            for (var si = 0; si < starts.Count; si++)
            {
                var start = starts[si];
                var end = (si + 1 < starts.Count) ? starts[si + 1] : uint.MaxValue;

                var summary = new FunctionSummary { Start = start };
                summaries[start] = summary;

                // Walk linear instruction list from first instruction >= start until end.
                for (var ii = 0; ii < instructions.Count; ii++)
                {
                    var ins = instructions[ii];
                    var addr = (uint)ins.Offset;
                    if (addr < start)
                        continue;
                    if (addr >= end)
                        break;

                    summary.InstructionCount++;

                    if (TryGetRelativeBranchTarget(ins, out var target, out var isCall) && isCall)
                        summary.Calls.Add(target);

                    if (sortedFixups != null)
                    {
                        // Very cheap: look for fixups that land within this instruction.
                        // (We don't want to advance a shared index here.)
                        var insStart = addr;
                        var insEnd = addr + (uint)ins.Length;
                        foreach (var f in sortedFixups)
                        {
                            if (f.SiteLinear < insStart)
                                continue;
                            if (f.SiteLinear >= insEnd)
                                break;
                            if (!f.Value32.HasValue)
                                continue;

                            if (globalSymbols != null && globalSymbols.TryGetValue(f.Value32.Value, out var g))
                                summary.Globals.Add(g);
                            if (stringSymbols != null && stringSymbols.TryGetValue(f.Value32.Value, out var s))
                                summary.Strings.Add(s);
                        }
                    }
                }

                if (blockStarts != null && blockStarts.Count > 0)
                    summary.BlockCount = blockStarts.Count(a => a >= start && a < end);
            }

            return summaries;
        }

        private static string TryGetCallArgHint(List<Instruction> instructions, Dictionary<uint, int> insIndexByAddr, Instruction ins, List<LEFixup> fixupsHere,
            Dictionary<uint, string> globalSymbols, Dictionary<uint, string> stringSymbols)
        {
            if (ins == null || instructions == null || insIndexByAddr == null)
                return string.Empty;

            // Only for call instructions.
            var text = ins.ToString();
            if (!text.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            if (!insIndexByAddr.TryGetValue((uint)ins.Offset, out var idx))
                return string.Empty;

            // Count push instructions immediately preceding within a short window.
            var pushes = 0;
            for (var i = idx - 1; i >= 0 && i >= idx - 8; i--)
            {
                var t = instructions[i].ToString();
                if (t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                {
                    pushes++;
                    continue;
                }
                // Stop if stack pointer adjusted or another call/ret/branch intervenes.
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase))
                    break;
                if (t.StartsWith("add esp", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub esp", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            // Heuristic for return usage: next instruction mentions eax.
            var retUsed = false;
            if (idx + 1 < instructions.Count)
            {
                var next = instructions[idx + 1].ToString();
                if (next.IndexOf("eax", StringComparison.OrdinalIgnoreCase) >= 0)
                    retUsed = true;
            }

            return $"args~{pushes} ret={(retUsed ? "eax" : "(unused?)")}";
        }

        private static string TryAnnotateInterrupt(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            var ins = instructions[idx];
            if (!TryGetIntNumber(ins, out var intNo))
                return string.Empty;

            // Database-driven descriptions first.
            byte? dbAh = null;
            ushort? dbAx = null;
            if (intNo == 0x21 || intNo == 0x10 || intNo == 0x16)
                dbAh = TryResolveAhBefore(instructions, idx);
            if (intNo == 0x31 || intNo == 0x33)
                dbAx = TryResolveAxBefore(instructions, idx);

            string db;
            if (DosInterruptDatabase.Instance.TryDescribe(intNo, dbAh, dbAx, out db) && !string.IsNullOrEmpty(db))
            {
                // Preserve existing prefixing style for readability in LE output.
                if (intNo == 0x21)
                    return "INT21: " + db;
                if (intNo == 0x31)
                    return "INT31: " + db;
                return "INT: " + db;
            }

            // BIOS/DOS/high-level tags
            if (intNo == 0x10)
                return "INT: BIOS video int 10h";
            if (intNo == 0x16)
                return "INT: BIOS keyboard int 16h";
            if (intNo == 0x33)
                return "INT: Mouse int 33h";

            if (intNo == 0x21)
            {
                var ah = TryResolveAhBefore(instructions, idx);
                if (!ah.HasValue)
                    return "INT21: DOS";

                var name = DescribeInt21Ah(ah.Value);
                return string.IsNullOrEmpty(name) ? $"INT21: AH=0x{ah.Value:X2}" : $"INT21: {name} (AH=0x{ah.Value:X2})";
            }

            if (intNo == 0x31)
            {
                var ax = TryResolveAxBefore(instructions, idx);
                if (!ax.HasValue)
                    return "INT31: DPMI";

                var name = DescribeInt31Ax(ax.Value);
                return string.IsNullOrEmpty(name) ? $"INT31: AX=0x{ax.Value:X4}" : $"INT31: {name} (AX=0x{ax.Value:X4})";
            }

            return $"INT: 0x{intNo:X2}";
        }

        private static bool TryGetIntNumber(Instruction ins, out byte intNo)
        {
            intNo = 0;
            if (ins?.Bytes == null || ins.Bytes.Length < 2)
                return false;

            var b = ins.Bytes;
            var p = 0;
            while (p < b.Length)
            {
                var x = b[p];
                // Common prefixes (same set as elsewhere)
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65)
                {
                    p++;
                    continue;
                }
                break;
            }

            if (p + 1 >= b.Length)
                return false;
            if (b[p] != 0xCD)
                return false;

            intNo = b[p + 1];
            return true;
        }

        private static byte? TryResolveAhBefore(List<Instruction> instructions, int idx)
        {
            // Look back a short window within the same straight-line region.
            for (var i = idx - 1; i >= 0 && i >= idx - 20; i--)
            {
                var ins = instructions[i];
                var b = ins.Bytes;
                if (b == null || b.Length == 0)
                    continue;

                // Barrier on control flow.
                var t = ins.ToString();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov ah, imm8  => B4 ib
                if (b.Length >= 2 && b[0] == 0xB4)
                    return b[1];

                // mov ax, imm16  => 66 B8 iw
                if (b.Length >= 4 && b[0] == 0x66 && b[1] == 0xB8)
                {
                    var ax = (ushort)(b[2] | (b[3] << 8));
                    return (byte)((ax >> 8) & 0xFF);
                }

                // mov eax, imm32 => B8 id
                if (b.Length >= 5 && b[0] == 0xB8)
                {
                    var eax = (uint)(b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));
                    return (byte)((eax >> 8) & 0xFF);
                }

                // xor ah, ah => 30 E4
                if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xE4)
                    return 0x00;
            }

            return null;
        }

        private static ushort? TryResolveAxBefore(List<Instruction> instructions, int idx)
        {
            for (var i = idx - 1; i >= 0 && i >= idx - 24; i--)
            {
                var ins = instructions[i];
                var b = ins.Bytes;
                if (b == null || b.Length == 0)
                    continue;

                var t = ins.ToString();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov ax, imm16 => 66 B8 iw
                if (b.Length >= 4 && b[0] == 0x66 && b[1] == 0xB8)
                    return (ushort)(b[2] | (b[3] << 8));

                // mov eax, imm32 => B8 id (use low 16)
                if (b.Length >= 5 && b[0] == 0xB8)
                {
                    var eax = (uint)(b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));
                    return (ushort)(eax & 0xFFFF);
                }
            }

            return null;
        }

        private static string DescribeInt21Ah(byte ah)
        {
            // Common DOS services (not exhaustive)
            switch (ah)
            {
                case 0x09: return "Display string ($-terminated)";
                case 0x0A: return "Buffered keyboard input";
                case 0x1A: return "Set DTA";
                case 0x2F: return "Get DTA";
                case 0x25: return "Set interrupt vector";
                case 0x35: return "Get interrupt vector";
                case 0x3C: return "Create file";
                case 0x3D: return "Open file";
                case 0x3E: return "Close file";
                case 0x3F: return "Read file/handle";
                case 0x40: return "Write file/handle";
                case 0x41: return "Delete file";
                case 0x42: return "Lseek";
                case 0x43: return "Get/Set file attributes";
                case 0x44: return "IOCTL";
                case 0x47: return "Get current directory";
                case 0x48: return "Allocate memory";
                case 0x49: return "Free memory";
                case 0x4A: return "Resize memory block";
                case 0x4B: return "Exec";
                case 0x4C: return "Terminate process";
                case 0x4E: return "Find first";
                case 0x4F: return "Find next";
                case 0x56: return "Rename file";
                case 0x57: return "Get/Set file date/time";
                default:
                    return string.Empty;
            }
        }

        private static string DescribeInt31Ax(ushort ax)
        {
            // Minimal, commonly encountered DPMI services (not exhaustive)
            switch (ax)
            {
                case 0x0000: return "Allocate LDT descriptors";
                case 0x0001: return "Free LDT descriptor";
                case 0x0007: return "Set segment base";
                case 0x0008: return "Set segment limit";
                case 0x0100: return "Allocate DOS memory block";
                case 0x0101: return "Free DOS memory block";
                case 0x0300: return "Simulate real-mode interrupt";
                case 0x0400: return "Get DPMI version";
                default:
                    return string.Empty;
            }
        }

        private static string TryAnnotateJumpTable(Instruction ins, List<LEFixup> fixupsHere, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> stringSymbols, Dictionary<uint, string> globalSymbols)
        {
            if (ins?.Bytes == null || ins.Bytes.Length < 6)
                return string.Empty;

            // Look for: FF 24 85 xx xx xx xx  (jmp dword [eax*4 + disp32])
            // ModRM=0x24 => rm=100 (SIB), reg=4 (JMP), mod=00
            var b = ins.Bytes;
            if (b[0] != 0xFF || b[1] != 0x24)
                return string.Empty;

            var sib = b[2];
            var scale = (sib >> 6) & 0x3;
            var baseReg = sib & 0x7;
            if (baseReg != 5)
                return string.Empty; // we only handle disp32 base

            if (scale != 2)
                return string.Empty; // scale 4 => likely jump table

            if (b.Length < 7)
                return string.Empty;

            var disp = (uint)(b[3] | (b[4] << 8) | (b[5] << 16) | (b[6] << 24));
            // disp is a linear address in flat model.
            if (!TryMapLinearToObject(objects, disp, out var tobj, out var toff))
                return $"JUMPTABLE: base=0x{disp:X8} (unmapped)";

            if (!objBytesByIndex.TryGetValue(tobj, out var tgtBytes) || tgtBytes == null)
                return $"JUMPTABLE: base=0x{disp:X8} (no bytes)";

            var max = 16;
            var entries = new List<uint>();
            for (var i = 0; i < max; i++)
            {
                var off = (int)toff + i * 4;
                if (off + 4 > tgtBytes.Length)
                    break;
                var v = (uint)(tgtBytes[off] | (tgtBytes[off + 1] << 8) | (tgtBytes[off + 2] << 16) | (tgtBytes[off + 3] << 24));
                // Only keep plausible in-module targets.
                if (!TryMapLinearToObject(objects, v, out var _, out var __))
                    break;
                entries.Add(v);
            }

            var sym = globalSymbols != null && globalSymbols.TryGetValue(disp, out var g) ? g : $"0x{disp:X8}";
            if (entries.Count == 0)
                return $"JUMPTABLE: base={sym} entries=0";

            var shown = string.Join(", ", entries.Select(x => $"0x{x:X8}").Take(8));
            return $"JUMPTABLE: base={sym} entries~{entries.Count} [{shown}{(entries.Count > 8 ? ", ..." : string.Empty)}]";
        }

        private static bool TryParseHexUInt(string s, out uint v)
        {
            v = 0;
            if (string.IsNullOrEmpty(s))
                return false;
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);
            return uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out v);
        }

        private static void RecordSymbolXrefs(Dictionary<string, HashSet<uint>> symXrefs, uint from, List<LEFixup> fixupsHere,
            Dictionary<uint, string> globalSymbols, Dictionary<uint, string> stringSymbols, Dictionary<uint, string> resourceSymbols)
        {
            if (symXrefs == null || fixupsHere == null || fixupsHere.Count == 0)
                return;

            foreach (var f in fixupsHere)
            {
                if (!f.Value32.HasValue)
                    continue;

                var v = f.Value32.Value;
                if (globalSymbols != null && globalSymbols.TryGetValue(v, out var g))
                    AddXref(symXrefs, g, from);
                if (stringSymbols != null && stringSymbols.TryGetValue(v, out var s))
                    AddXref(symXrefs, s, from);
                if (resourceSymbols != null && resourceSymbols.TryGetValue(v, out var r))
                    AddXref(symXrefs, r, from);
            }
        }

        private static void AddXref(Dictionary<string, HashSet<uint>> symXrefs, string sym, uint from)
        {
            if (string.IsNullOrEmpty(sym))
                return;
            if (!symXrefs.TryGetValue(sym, out var set))
                symXrefs[sym] = set = new HashSet<uint>();
            set.Add(from);
        }

        private static readonly Regex HexLiteralRegex = new Regex("0x[0-9A-Fa-f]{1,8}", RegexOptions.Compiled);

        private static string RewriteKnownAddressLiterals(string insText, Dictionary<uint, string> globalSymbols, Dictionary<uint, string> stringSymbols, Dictionary<uint, string> resourceSymbols = null)
        {
            if (string.IsNullOrEmpty(insText))
                return insText;
            if ((globalSymbols == null || globalSymbols.Count == 0) && (stringSymbols == null || stringSymbols.Count == 0) && (resourceSymbols == null || resourceSymbols.Count == 0))
                return insText;

            return HexLiteralRegex.Replace(insText, m =>
            {
                if (!TryParseHexUInt(m.Value, out var v))
                    return m.Value;

                // Prefer string symbols over globals when both exist.
                if (stringSymbols != null && stringSymbols.TryGetValue(v, out var s))
                    return s;
                if (resourceSymbols != null && resourceSymbols.TryGetValue(v, out var r))
                    return r;
                if (globalSymbols != null && globalSymbols.TryGetValue(v, out var g))
                    return g;

                return m.Value;
            });
        }

        private sealed class LEFixup
        {
            public uint SourceLinear;
            public ushort SourceOffsetInPage;
            public uint PageNumber; // 1-based physical page
            public uint SiteLinear;
            public byte SiteDelta;
            public uint? Value32;
            public int? TargetObject;
            public uint? TargetOffset;
            public byte Type;
            public byte Flags;
        }

        private struct LEHeader
        {
            public int HeaderOffset;
            public uint ModuleFlags;
            public uint NumberOfPages;
            public uint EntryEipObject;
            public uint EntryEip;
            public uint EntryEspObject;
            public uint EntryEsp;
            public uint PageSize;
            public uint LastPageSize;
            public uint ObjectTableOffset;
            public uint ObjectCount;
            public uint ObjectPageMapOffset;
            public uint FixupPageTableOffset;
            public uint FixupRecordTableOffset;
            public uint ImportModuleTableOffset;
            public uint ImportModuleTableEntries;
            public uint ImportProcTableOffset;
            public uint DataPagesOffset;
        }

        private struct LEObject
        {
            public int Index;
            public uint VirtualSize;
            public uint BaseAddress;
            public uint Flags;
            public uint PageMapIndex; // 1-based
            public uint PageCount;
        }

        public static bool TryDumpFixupsToString(string inputFile, int? maxPages, int maxBytesPerPage, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (!File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

            if (maxBytesPerPage <= 0)
                maxBytesPerPage = 256;

            var fileBytes = File.ReadAllBytes(inputFile);
            if (!TryFindLEHeaderOffset(fileBytes, out var leHeaderOffset))
            {
                error = "LE header not found";
                return false;
            }

            if (!TryParseHeader(fileBytes, leHeaderOffset, out var header, out error))
                return false;

            var objects = ParseObjects(fileBytes, header);
            var pageMap = ParseObjectPageMap(fileBytes, header);

            var sb = new StringBuilder();
            sb.AppendLine($"; LE FIXUP DUMP (DOS4GW-focused) - {Path.GetFileName(inputFile)}");
            sb.AppendLine($"; HeaderOffset: 0x{header.HeaderOffset:X}");
            sb.AppendLine($"; Pages: {header.NumberOfPages}  PageSize: {header.PageSize}  LastPageSize: {header.LastPageSize}");
            sb.AppendLine($"; FixupPageTableOffset: 0x{header.FixupPageTableOffset:X}  FixupRecordTableOffset: 0x{header.FixupRecordTableOffset:X}");
            sb.AppendLine($"; ImportModuleTableOffset: 0x{header.ImportModuleTableOffset:X}  Entries: {header.ImportModuleTableEntries}");
            sb.AppendLine($"; ImportProcTableOffset: 0x{header.ImportProcTableOffset:X}");
            sb.AppendLine(";");

            var importModules = TryParseImportModules(fileBytes, header);
            if (importModules != null && importModules.Count > 0)
            {
                sb.AppendLine("; Import Modules");
                for (var i = 0; i < importModules.Count; i++)
                {
                    var name = string.IsNullOrEmpty(importModules[i]) ? "(empty)" : importModules[i];
                    sb.AppendLine($";   [{i + 1}] {name}");
                }
                sb.AppendLine(";");
            }

            if (!TryGetFixupStreams(fileBytes, header, out var fixupPageOffsets, out var fixupRecordStream) || fixupPageOffsets == null || fixupRecordStream == null)
            {
                sb.AppendLine("; No fixup streams available (or failed to parse fixup tables)");
                output = sb.ToString();
                return true;
            }

            var recordFileStart = header.HeaderOffset + (int)header.FixupRecordTableOffset;
            sb.AppendLine($"; Fixup record stream length: 0x{fixupRecordStream.Length:X} ({fixupRecordStream.Length} bytes)");
            sb.AppendLine($"; Fixup record stream file offset: 0x{recordFileStart:X}");
            sb.AppendLine(";");

            sb.AppendLine("; Objects (for context)");
            foreach (var obj in objects)
                sb.AppendLine($";   Obj{obj.Index} Base=0x{obj.BaseAddress:X8} Size=0x{obj.VirtualSize:X} PageMapIndex={obj.PageMapIndex} PageCount={obj.PageCount} Flags=0x{obj.Flags:X8}");
            sb.AppendLine(";");

            var pagesToDump = (int)header.NumberOfPages;
            if (maxPages.HasValue && maxPages.Value > 0)
                pagesToDump = Math.Min(pagesToDump, maxPages.Value);

            sb.AppendLine("; Per-page fixup slices");
            sb.AppendLine("; NOTE: LE fixup page table is indexed by *logical page number* (1..NumberOfPages)");
            sb.AppendLine("; NOTE: Below includes a stride auto-detect (candidates: 8/10/12/16) and a stride-based view.");
            sb.AppendLine(";");

            var strideCounts = new Dictionary<int, int>();

            for (var page1 = 1; page1 <= pagesToDump; page1++)
            {
                var idx0 = page1 - 1;
                if (idx0 + 1 >= fixupPageOffsets.Length)
                    break;

                var start = fixupPageOffsets[idx0];
                var end = fixupPageOffsets[idx0 + 1];
                if (end <= start)
                    continue;

                if (end > (uint)fixupRecordStream.Length)
                    continue;

                var len = (int)(end - start);
                sb.AppendLine($"; -------- Page {page1} --------");
                sb.AppendLine($"; RecordStreamOff: 0x{start:X}..0x{end:X} (len=0x{len:X})");

                var strideGuess = GuessStride(fixupRecordStream, (int)start, len, (int)header.PageSize);
                if (!strideCounts.ContainsKey(strideGuess.Stride))
                    strideCounts[strideGuess.Stride] = 0;
                strideCounts[strideGuess.Stride]++;
                sb.AppendLine($"; Best stride guess: {strideGuess.Stride} bytes (score={strideGuess.Score:0.00}, validSrcOff={strideGuess.ValidSrcOff}/{strideGuess.EntriesChecked})");

                // Raw hexdump (capped)
                var dumpLen = Math.Min(len, maxBytesPerPage);
                sb.AppendLine($"; Raw bytes (first {dumpLen} of {len})");
                sb.AppendLine(HexDump(fixupRecordStream, (int)start, dumpLen));

                sb.AppendLine($"; Stride-based view (stride={strideGuess.Stride})");
                sb.AppendLine(DumpStrideView(fixupRecordStream, (int)start, (int)end, strideGuess.Stride, 64));

                sb.AppendLine(";");
            }

            if (strideCounts.Count > 0)
            {
                sb.AppendLine("; -------- Stride summary --------");
                foreach (var kvp in strideCounts.OrderBy(k => k.Key))
                    sb.AppendLine($"; stride {kvp.Key}: {kvp.Value} page(s)");
                sb.AppendLine(";");
            }

            output = sb.ToString();
            return true;
        }

        private readonly struct StrideGuess
        {
            public int Stride { get; }
            public double Score { get; }
            public int ValidSrcOff { get; }
            public int EntriesChecked { get; }

            public StrideGuess(int stride, double score, int validSrcOff, int entriesChecked)
            {
                Stride = stride;
                Score = score;
                ValidSrcOff = validSrcOff;
                EntriesChecked = entriesChecked;
            }
        }

        private static StrideGuess GuessStride(byte[] data, int start, int len, int pageSize)
        {
            // DOS4GW fixup record streams often appear to be fixed-stride within a page.
            // We'll score likely strides based on whether the 16-bit source offset field looks plausible.
            var candidates = new[] { 8, 10, 12, 16 };
            var best = new StrideGuess(16, double.NegativeInfinity, 0, 0);

            foreach (var stride in candidates)
            {
                if (stride <= 0 || len < stride)
                    continue;

                var entries = Math.Min(len / stride, 128);
                var checkedEntries = 0;
                var validSrcOff = 0;
                double score = 0;

                for (var i = 0; i < entries; i++)
                {
                    var off = start + i * stride;
                    if (off + 4 > start + len)
                        break;

                    var srcType = data[off + 0];
                    var flags = data[off + 1];
                    var srcOff = (ushort)(data[off + 2] | (data[off + 3] << 8));

                    checkedEntries++;

                    // Source offset should generally be within the page.
                    if (srcOff < pageSize)
                    {
                        validSrcOff++;
                        score += 2.0;
                    }
                    else
                    {
                        score -= 2.0;
                    }

                    // Mild preference for non-trivial values (avoid matching on all-zeros garbage).
                    if (srcType != 0x00 && srcType != 0xFF)
                        score += 0.25;
                    if (flags != 0x00 && flags != 0xFF)
                        score += 0.10;
                }

                if (len % stride == 0)
                    score += 5.0;

                // Prefer higher valid ratio.
                if (checkedEntries > 0)
                    score += 5.0 * ((double)validSrcOff / checkedEntries);

                if (score > best.Score)
                    best = new StrideGuess(stride, score, validSrcOff, checkedEntries);
            }

            // Fallback
            if (double.IsNegativeInfinity(best.Score))
                return new StrideGuess(16, 0, 0, 0);

            return best;
        }

        private static string DumpStrideView(byte[] data, int start, int end, int stride, int maxEntries)
        {
            if (data == null || stride <= 0 || start < 0 || end > data.Length || end <= start)
                return string.Empty;

            var sb = new StringBuilder();
            var len = end - start;
            var entries = Math.Min(len / stride, maxEntries);

            for (var i = 0; i < entries; i++)
            {
                var off = start + i * stride;
                if (off + stride > end)
                    break;

                var srcType = data[off + 0];
                var flags = data[off + 1];
                var srcOff = (ushort)(data[off + 2] | (data[off + 3] << 8));
                var restLen = Math.Max(0, stride - 4);
                var rest = restLen == 0 ? string.Empty : BitConverter.ToString(data, off + 4, restLen).Replace("-", " ");

                sb.AppendLine($";   [{i:00}] +0x{(off - start):X3}  type=0x{srcType:X2} flags=0x{flags:X2} srcOff=0x{srcOff:X4}  rest={rest}");
            }

            return sb.ToString().TrimEnd();
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, bool leFixups, bool leGlobals, bool leInsights, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (!File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

            var fileBytes = File.ReadAllBytes(inputFile);
            if (!TryFindLEHeaderOffset(fileBytes, out var leHeaderOffset))
            {
                error = "LE header not found";
                return false;
            }

            if (!TryParseHeader(fileBytes, leHeaderOffset, out var header, out error))
                return false;

            var objects = ParseObjects(fileBytes, header);
            var pageMap = ParseObjectPageMap(fileBytes, header);

            List<string> importModules = null;
            byte[] fixupRecordStream = null;
            uint[] fixupPageOffsets = null;

            if (leFixups)
            {
                importModules = TryParseImportModules(fileBytes, header);
                TryGetFixupStreams(fileBytes, header, out fixupPageOffsets, out fixupRecordStream);
            }

            var dataPagesBase = header.HeaderOffset + (int)header.DataPagesOffset;
            if (dataPagesBase <= 0 || dataPagesBase >= fileBytes.Length)
            {
                error = "Invalid LE data pages offset";
                return false;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (LE / DOS4GW)");
            sb.AppendLine($"; PageSize: {header.PageSize}  LastPageSize: {header.LastPageSize}  Pages: {header.NumberOfPages}");
            sb.AppendLine($"; Entry: Obj {header.EntryEipObject} + 0x{header.EntryEip:X} (Linear 0x{ComputeEntryLinear(header, objects):X})");
            if (leFixups)
                sb.AppendLine($"; NOTE: LE fixup annotations enabled (best-effort)");
            else
                sb.AppendLine($"; NOTE: Minimal LE support (no fixups/import analysis)");

            if (leGlobals)
                sb.AppendLine($"; NOTE: LE globals enabled (disp32 fixups become g_XXXXXXXX symbols)");
            if (leInsights)
                sb.AppendLine($"; NOTE: LE insights enabled (best-effort function/CFG/xref/stack-var/string analysis)");
            sb.AppendLine($"; XREFS: derived from relative CALL/JMP/Jcc only");
            if (leFull)
                sb.AppendLine("; LE mode: FULL (disassemble from object start)");
            if (!leFull && leBytesLimit.HasValue)
                sb.AppendLine($"; LE mode: LIMIT {leBytesLimit.Value} bytes");
            sb.AppendLine(";");

            // Reconstruct all object bytes once so we can scan data objects (strings) and map xrefs.
            var objBytesByIndex = new Dictionary<int, byte[]>();
            foreach (var o in objects)
            {
                if (o.VirtualSize == 0 || o.PageCount == 0)
                    continue;
                var bytes = ReconstructObjectBytes(fileBytes, header, pageMap, dataPagesBase, o);
                if (bytes != null && bytes.Length > 0)
                    objBytesByIndex[o.Index] = bytes;
            }

            // String symbol table (linear address -> symbol)
            Dictionary<uint, string> stringSymbols = null;
            Dictionary<uint, string> stringPreview = null;
            Dictionary<uint, string> resourceSymbols = null;
            Dictionary<uint, string> vtblSymbols = null;
            Dictionary<uint, Dictionary<uint, uint>> vtblSlots = null;
            Dictionary<uint, string> dispatchTableNotes = null;
            Dictionary<uint, string> dispatchTableSymbols = null;
            if (leInsights)
            {
                ScanStrings(objects, objBytesByIndex, out stringSymbols, out stringPreview);
                resourceSymbols = new Dictionary<uint, string>();
                vtblSymbols = new Dictionary<uint, string>();
                vtblSlots = new Dictionary<uint, Dictionary<uint, uint>>();
                dispatchTableNotes = new Dictionary<uint, string>();
                dispatchTableSymbols = new Dictionary<uint, string>();
                if (stringSymbols.Count > 0)
                {
                    sb.AppendLine("; Strings (best-effort, ASCII/CP437-ish)");
                    foreach (var kvp in stringSymbols.OrderBy(k => k.Key).Take(512))
                    {
                        var prev = stringPreview.TryGetValue(kvp.Key, out var p) ? p : string.Empty;
                        if (!string.IsNullOrEmpty(prev))
                            sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8} ; \"{prev}\"");
                        else
                            sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8}");
                    }
                    if (stringSymbols.Count > 512)
                        sb.AppendLine($"; (strings truncated: {stringSymbols.Count} total)");
                    sb.AppendLine(";");
                }
            }

            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0 || obj.PageCount == 0)
                    continue;

                // Heuristic: treat objects with the EXECUTABLE bit (0x0004) as code.
                // Some toolchains may set different flags; if this is wrong, we still allow disassembling.
                var isExecutable = (obj.Flags & 0x0004) != 0;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes))
                    objBytes = null;
                if (objBytes == null || objBytes.Length == 0)
                    continue;

                // Trim to virtual size when possible
                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)objBytes.Length);
                if (maxLen <= 0)
                    continue;

                var startOffsetWithinObject = 0;
                if (!leFull)
                {
                    if (header.EntryEipObject == (uint)obj.Index && header.EntryEip < (uint)maxLen)
                    {
                        startOffsetWithinObject = (int)header.EntryEip;
                    }
                    else
                    {
                        // Heuristic: avoid producing huge runs of "add [eax], al" from zero-filled regions.
                        for (var i = 0; i < maxLen; i++)
                        {
                            if (objBytes[i] != 0)
                            {
                                startOffsetWithinObject = i;
                                break;
                            }
                        }
                    }
                }

                sb.AppendLine(";-------------------------------------------");
                sb.AppendLine($"; Object {obj.Index}  Base: 0x{obj.BaseAddress:X8}  Size: 0x{obj.VirtualSize:X}  Flags: 0x{obj.Flags:X8}  Pages: {obj.PageCount}  {(isExecutable ? "CODE" : "DATA?")}");
                sb.AppendLine($"; Disassembly start: +0x{startOffsetWithinObject:X} (Linear 0x{(obj.BaseAddress + (uint)startOffsetWithinObject):X8})");
                sb.AppendLine("; LINEAR_ADDR BYTES DISASSEMBLY");
                sb.AppendLine(";-------------------------------------------");

                if (!isExecutable)
                {
                    sb.AppendLine("; Skipping non-executable object (use -minimal later if you want raw dump support)");
                    sb.AppendLine();
                    continue;
                }

                var codeLen = maxLen - startOffsetWithinObject;
                if (!leFull && leBytesLimit.HasValue)
                    codeLen = Math.Min(codeLen, leBytesLimit.Value);
                if (codeLen <= 0)
                {
                    sb.AppendLine("; (No bytes to disassemble)");
                    sb.AppendLine();
                    continue;
                }

                var code = new byte[codeLen];
                Buffer.BlockCopy(objBytes, startOffsetWithinObject, code, 0, codeLen);

                var startLinear = obj.BaseAddress + (uint)startOffsetWithinObject;
                var endLinear = startLinear + (uint)codeLen;

                List<LEFixup> objFixups = null;
                if (leFixups && fixupRecordStream != null && fixupPageOffsets != null)
                {
                    objFixups = ParseFixupsForWindow(
                        header,
                        objects,
                        pageMap,
                        importModules,
                        fileBytes,
                        fixupPageOffsets,
                        fixupRecordStream,
                    objBytes,
                        obj,
                        startLinear,
                        endLinear);
                }

                // First pass: disassemble and collect basic xrefs and function/label targets.
                var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_32, startLinear, true);
                var instructions = dis.Disassemble().ToList();

                // Address->instruction index for fast lookups.
                var insIndexByAddr = new Dictionary<uint, int>(instructions.Count);
                for (var ii = 0; ii < instructions.Count; ii++)
                    insIndexByAddr[(uint)instructions[ii].Offset] = ii;

                var functionStarts = new HashSet<uint>();
                var labelTargets = new HashSet<uint>();
                var callXrefs = new Dictionary<uint, List<uint>>();
                var jumpXrefs = new Dictionary<uint, List<uint>>();

                if (header.EntryEipObject == (uint)obj.Index)
                {
                    var entryLinear = obj.BaseAddress + header.EntryEip;
                    if (entryLinear >= startLinear && entryLinear < endLinear)
                        functionStarts.Add(entryLinear);
                }

                if (leInsights)
                {
                    // Add obvious prologues as function starts: 55 8B EC
                    foreach (var ins in instructions)
                    {
                        var b = ins.Bytes;
                        if (b != null && b.Length >= 3 && b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC)
                            functionStarts.Add((uint)ins.Offset);
                    }
                }

                foreach (var ins in instructions)
                {
                    if (TryGetRelativeBranchTarget(ins, out var target, out var isCall))
                    {
                        if (target >= startLinear && target < endLinear)
                        {
                            if (isCall)
                            {
                                functionStarts.Add(target);
                                if (!callXrefs.TryGetValue(target, out var callers))
                                    callXrefs[target] = callers = new List<uint>();
                                callers.Add((uint)ins.Offset);
                            }
                            else
                            {
                                labelTargets.Add(target);
                                if (!jumpXrefs.TryGetValue(target, out var sources))
                                    jumpXrefs[target] = sources = new List<uint>();
                                sources.Add((uint)ins.Offset);
                            }
                        }
                    }
                }

                // Basic-block starts (for insights mode)
                HashSet<uint> blockStarts = null;
                Dictionary<uint, List<uint>> blockPreds = null;
                if (leInsights)
                {
                    BuildBasicBlocks(instructions, startLinear, endLinear, functionStarts, labelTargets, out blockStarts, out blockPreds);
                }

                // Second pass: render with labels and inline xref hints.
                var sortedFixups = objFixups == null ? null : objFixups.OrderBy(f => f.SiteLinear).ToList();

                // Map instruction offset -> fixups that touch bytes within that instruction.
                Dictionary<uint, List<LEFixup>> fixupsByInsAddr = null;
                if (leInsights && sortedFixups != null && sortedFixups.Count > 0)
                    fixupsByInsAddr = BuildFixupLookupByInstruction(instructions, sortedFixups);

                HashSet<uint> resourceGetterTargets = null;
                if (leInsights)
                    resourceGetterTargets = DetectResourceGetterTargets(instructions);

                Dictionary<uint, string> globalSymbols = null;
                if (leGlobals && sortedFixups != null && sortedFixups.Count > 0)
                {
                    globalSymbols = CollectGlobalSymbols(instructions, sortedFixups);
                    if (globalSymbols.Count > 0)
                    {
                        sb.AppendLine("; Globals (derived from disp32 fixups)");
                        foreach (var kvp in globalSymbols.OrderBy(k => k.Key))
                            sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8}");
                        sb.AppendLine(";");
                    }
                }

                // dispatchTableNotes/dispatchTableSymbols are per-run caches (declared above).

                var fixupIdx = 0;

                // Cross references to symbols (insights)
                Dictionary<string, HashSet<uint>> symXrefs = null;
                if (leInsights)
                    symXrefs = new Dictionary<string, HashSet<uint>>(StringComparer.Ordinal);

                // Per-function summaries (insights)
                Dictionary<uint, FunctionSummary> funcSummaries = null;
                if (leInsights)
                {
                    funcSummaries = SummarizeFunctions(instructions, functionStarts, blockStarts, sortedFixups, globalSymbols, stringSymbols);
                }

                // Per-function field summaries (insights)
                Dictionary<uint, string> funcFieldSummaries = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcFieldSummaries = new Dictionary<uint, string>();
                    var sortedStarts = functionStarts.OrderBy(x => x).ToList();
                    for (var si = 0; si < sortedStarts.Count; si++)
                    {
                        var startAddr = sortedStarts[si];
                        if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                            continue;

                        var endIdx = instructions.Count;
                        if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                            endIdx = nextIdx;

                        CollectFieldAccessesForFunction(instructions, startIdx, endIdx, out var stats);
                        var summary = FormatFieldSummary(stats);
                        if (!string.IsNullOrEmpty(summary))
                            funcFieldSummaries[startAddr] = summary;
                    }
                }

                // Live alias tracking for operand rewriting during rendering.
                var liveAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ecx"] = "this"
                };

                for (var insLoopIndex = 0; insLoopIndex < instructions.Count; insLoopIndex++)
                {
                    var ins = instructions[insLoopIndex];
                    var addr = (uint)ins.Offset;

                    if (functionStarts.Contains(addr))
                    {
                        sb.AppendLine();
                        sb.AppendLine($"func_{addr:X8}:");
                        if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                            sb.AppendLine($"; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}");

                        if (leInsights && resourceGetterTargets != null && resourceGetterTargets.Contains(addr))
                            sb.AppendLine("; ROLE: res_get(base=edx, id=eax) -> eax (best-effort)");

                        if (leInsights && funcSummaries != null && funcSummaries.TryGetValue(addr, out var summary))
                            sb.AppendLine(summary.ToComment());

                        if (leInsights && funcFieldSummaries != null && funcFieldSummaries.TryGetValue(addr, out var fsum))
                            sb.AppendLine($"; {fsum}");

                        // Reset aliases at function boundary.
                        liveAliases.Clear();
                        liveAliases["ecx"] = "this";
                    }
                    else if (labelTargets.Contains(addr))
                    {
                        sb.AppendLine($"loc_{addr:X8}:");
                        if (jumpXrefs.TryGetValue(addr, out var sources) && sources.Count > 0)
                            sb.AppendLine($"; XREF: jumped from {string.Join(", ", sources.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}");
                    }
                    else if (leInsights && blockStarts != null && blockStarts.Contains(addr))
                    {
                        sb.AppendLine($"bb_{addr:X8}:");
                        if (blockPreds != null && blockPreds.TryGetValue(addr, out var preds) && preds.Count > 0)
                            sb.AppendLine($"; CFG: preds {string.Join(", ", preds.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}");
                    }

                    var bytes = BitConverter.ToString(ins.Bytes).Replace("-", string.Empty);
                    var insText = ins.ToString();

                    if (leInsights)
                    {
                        insText = RewriteStackFrameOperands(insText);

                        // Update aliases based on the *current* instruction before rewriting.
                        UpdatePointerAliases(insText, liveAliases);

                        // Rewrite [reg+disp] into [this/argX + field_..] when it looks like a struct access.
                        insText = RewriteFieldOperands(insText, liveAliases);
                    }

                    if (TryGetRelativeBranchTarget(ins, out var branchTarget, out var isCall2))
                    {
                        var label = isCall2 ? $"func_{branchTarget:X8}" : $"loc_{branchTarget:X8}";
                        insText += $" ; {(isCall2 ? "call" : "jmp")} {label}";
                    }

                    var haveFixups = sortedFixups != null && sortedFixups.Count > 0;
                    var fixupsHere = haveFixups ? GetFixupsForInstruction(sortedFixups, ins, ref fixupIdx) : new List<LEFixup>(0);

                    if (leGlobals && globalSymbols != null && globalSymbols.Count > 0 && fixupsHere.Count > 0)
                        insText = ApplyGlobalSymbolRewrites(ins, insText, fixupsHere, globalSymbols);

                    if (leInsights)
                    {
                        // Fixup-based string rewrites (optional)
                        if (fixupsHere.Count > 0)
                            insText = ApplyStringSymbolRewrites(ins, insText, fixupsHere, stringSymbols, objects);

                        // Replace any matching 0x... literal with known symbol.
                        insText = RewriteKnownAddressLiterals(insText, globalSymbols, stringSymbols, resourceSymbols);

                        // Record xrefs from fixups -> symbols
                        if (symXrefs != null && fixupsHere.Count > 0)
                            RecordSymbolXrefs(symXrefs, (uint)ins.Offset, fixupsHere, globalSymbols, stringSymbols, resourceSymbols);

                        var callHint = TryGetCallArgHint(instructions, insIndexByAddr, ins, fixupsHere, globalSymbols, stringSymbols);
                        if (!string.IsNullOrEmpty(callHint))
                            insText += $" ; CALLHINT: {callHint}";

                        var stackHint = TryAnnotateCallStackCleanup(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(stackHint))
                            insText += $" ; {stackHint}";

                        var dispatchHint = TryAnnotateDispatchTableCall(instructions, insLoopIndex, globalSymbols, objects, objBytesByIndex, dispatchTableNotes, dispatchTableSymbols);
                        if (!string.IsNullOrEmpty(dispatchHint))
                            insText += $" ; {dispatchHint}";

                        var vcall = TryAnnotateVirtualCallDetailed(instructions, insLoopIndex, objects, objBytesByIndex, fixupsByInsAddr, vtblSymbols, vtblSlots);
                        if (!string.IsNullOrEmpty(vcall))
                        {
                            insText += $" ; {vcall}";
                        }
                        else
                        {
                            // Fallback: still mark indirect calls even when we can't resolve the vtable.
                            var virtHint = TryAnnotateVirtualCall(instructions, insLoopIndex);
                            if (!string.IsNullOrEmpty(virtHint))
                                insText += $" ; {virtHint}";
                        }

                        var resStrHint = TryAnnotateResourceStringCall(instructions, insLoopIndex, stringSymbols, stringPreview, objects, objBytesByIndex, resourceSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(resStrHint))
                            insText += $" ; {resStrHint}";

                        var fmtHint = TryAnnotateFormatCall(instructions, insLoopIndex, globalSymbols, stringSymbols, stringPreview, objects, objBytesByIndex, resourceSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(fmtHint))
                            insText += $" ; {fmtHint}";

                        var jt = TryAnnotateJumpTable(ins, fixupsHere, objects, objBytesByIndex, stringSymbols, globalSymbols);
                        if (!string.IsNullOrEmpty(jt))
                            insText += $" ; {jt}";

                        var intHint = TryAnnotateInterrupt(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(intHint))
                            insText += $" ; {intHint}";

                        // If this instruction references a string symbol (or computes one), inline a short preview.
                        var strInline = TryInlineStringPreview(insText, stringPreview, objects, objBytesByIndex, instructions, insLoopIndex, stringSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(strInline))
                            insText += $" ; {strInline}";
                    }

                    if (haveFixups && fixupsHere.Count > 0)
                    {
                        var fixupText = FormatFixupAnnotation(ins, fixupsHere);
                        if (!string.IsNullOrEmpty(fixupText))
                            insText += $" ; FIXUP: {fixupText}";
                    }

                    var line = $"{ins.Offset:X8}h {bytes.PadRight(Constants.MAX_INSTRUCTION_LENGTH, ' ')} {insText}";

                    sb.AppendLine(line);
                }

                if (leInsights && symXrefs != null && symXrefs.Count > 0)
                {
                    sb.AppendLine(";");
                    sb.AppendLine("; Symbol XREFS (within this object, best-effort)");

                    foreach (var kvp in symXrefs.OrderByDescending(k => k.Value.Count).ThenBy(k => k.Key).Take(64))
                    {
                        var refs = kvp.Value.OrderBy(x => x).Take(12).Select(x => $"0x{x:X8}");
                        sb.AppendLine($";   {kvp.Key} ({kvp.Value.Count}) <- {string.Join(", ", refs)}{(kvp.Value.Count > 12 ? ", ..." : string.Empty)}");
                    }

                    if (symXrefs.Count > 64)
                        sb.AppendLine($";   (xref table truncated: {symXrefs.Count} symbols)");
                }

                sb.AppendLine();
            }

            if (leInsights && dispatchTableSymbols != null && dispatchTableSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; Dispatch Tables (best-effort: inferred from indexed indirect calls)");

                foreach (var kvp in dispatchTableSymbols.OrderBy(k => k.Key).Take(256))
                {
                    var baseAddr = kvp.Key;
                    var sym = kvp.Value;
                    var note = dispatchTableNotes != null && dispatchTableNotes.TryGetValue(baseAddr, out var n) ? n : string.Empty;
                    if (!string.IsNullOrEmpty(note))
                        sb.AppendLine($"{sym} EQU 0x{baseAddr:X8} ;{note.TrimStart()}");
                    else
                        sb.AppendLine($"{sym} EQU 0x{baseAddr:X8}");
                }

                if (dispatchTableSymbols.Count > 256)
                    sb.AppendLine($"; (dispatch tables truncated: {dispatchTableSymbols.Count} total)");
                sb.AppendLine(";");
            }

            if (leInsights && vtblSymbols != null && vtblSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; VTables (best-effort: inferred from constructor writes + indirect calls)");

                foreach (var kvp in vtblSymbols.OrderBy(k => k.Key).Take(128))
                {
                    var vtblAddr = kvp.Key;
                    var vtblSym = kvp.Value;
                    sb.AppendLine($"; {vtblSym} = 0x{vtblAddr:X8}");

                    if (vtblSlots != null && vtblSlots.TryGetValue(vtblAddr, out var slots) && slots.Count > 0)
                    {
                        foreach (var s in slots.OrderBy(x => x.Key).Take(32))
                        {
                            var slot = s.Key;
                            var target = s.Value;
                            sb.AppendLine($";   slot 0x{slot:X} -> func_{target:X8}");
                        }
                        if (slots.Count > 32)
                            sb.AppendLine($";   (slots truncated: {slots.Count} total)");
                    }
                }
                if (vtblSymbols.Count > 128)
                    sb.AppendLine($"; (vtables truncated: {vtblSymbols.Count} total)");
                sb.AppendLine(";");
            }

            if (leInsights && resourceSymbols != null && resourceSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; Resource Symbols (best-effort: inferred from resource-getter call patterns)");
                foreach (var kvp in resourceSymbols.OrderBy(k => k.Key).Take(1024))
                {
                    var addr2 = kvp.Key;
                    var sym2 = kvp.Value;
                    var prev2 = (stringPreview != null && stringPreview.TryGetValue(addr2, out var p2)) ? p2 : string.Empty;
                    if (!string.IsNullOrEmpty(prev2))
                        sb.AppendLine($"{sym2} EQU 0x{addr2:X8} ; \"{prev2}\"");
                    else
                        sb.AppendLine($"{sym2} EQU 0x{addr2:X8}");
                }
                if (resourceSymbols.Count > 1024)
                    sb.AppendLine($"; (resource symbols truncated: {resourceSymbols.Count} total)");
                sb.AppendLine(";");
            }

            output = sb.ToString();
            return true;
        }

        private static Dictionary<uint, List<LEFixup>> BuildFixupLookupByInstruction(List<Instruction> instructions, List<LEFixup> sortedFixups)
        {
            if (instructions == null || instructions.Count == 0 || sortedFixups == null || sortedFixups.Count == 0)
                return null;

            // Build a sorted list of instruction start addresses for binary search.
            var starts = new uint[instructions.Count];
            for (var i = 0; i < instructions.Count; i++)
                starts[i] = (uint)instructions[i].Offset;

            var map = new Dictionary<uint, List<LEFixup>>();
            foreach (var f in sortedFixups)
            {
                var site = f.SiteLinear;
                var idx = Array.BinarySearch(starts, site);
                if (idx < 0)
                    idx = ~idx - 1;
                if (idx < 0 || idx >= instructions.Count)
                    continue;

                var ins = instructions[idx];
                var begin = (uint)ins.Offset;
                var len = (uint)(ins.Bytes?.Length ?? 0);
                if (len == 0)
                    continue;

                // Site must fall within the instruction byte range.
                if (site < begin || site >= begin + len)
                    continue;

                if (!map.TryGetValue(begin, out var list))
                    map[begin] = list = new List<LEFixup>();
                list.Add(f);
            }

            return map;
        }

        private static string TryAnnotateDispatchTableCall(
            List<Instruction> instructions,
            int callIdx,
            Dictionary<uint, string> globalSymbols,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> dispatchTableNotes,
            Dictionary<uint, string> dispatchTableSymbols)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = instructions[callIdx].ToString().Trim();
            var mc = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9a-fA-F]+))?\]$", RegexOptions.IgnoreCase);
            if (!mc.Success)
                return string.Empty;

            var callBase = mc.Groups["base"].Value.ToLowerInvariant();
            var callDisp = 0u;
            if (mc.Groups["disp"].Success)
                callDisp = Convert.ToUInt32(mc.Groups["disp"].Value, 16);

            // Look back for an indexed table load into the call base register, e.g.:
            //   mov edx, [edx*4+0xc3040]
            //   mov eax, [ecx+edx*4+0xNN]
            // (We mainly care about a constant base because that implies a dispatch table.)
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 6; i--)
            {
                var t = instructions[i].ToString().Trim();

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov dst, [idx*scale + 0xBASE]
                var m1 = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<idx>e[a-z]{2})\*(?<scale>[1248])\+0x(?<base>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (!m1.Success)
                {
                    // mov dst, [base+idx*scale+0xDISP]
                    m1 = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<basereg>e[a-z]{2})\+(?<idx>e[a-z]{2})\*(?<scale>[1248])\+0x(?<base>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                }
                if (!m1.Success)
                    continue;

                var dst = m1.Groups["dst"].Value.ToLowerInvariant();
                if (dst != callBase)
                    continue;

                var idxReg = m1.Groups["idx"].Value.ToLowerInvariant();
                var scale = Convert.ToInt32(m1.Groups["scale"].Value, 10);
                var baseHex = m1.Groups["base"].Value;
                if (!TryParseHexUInt("0x" + baseHex, out var baseAddrU))
                    continue;
                var baseAddr = (uint)baseAddrU;

                if (dispatchTableSymbols != null && !dispatchTableSymbols.ContainsKey(baseAddr))
                {
                    if (objects != null && TryMapLinearToObject(objects, baseAddr, out var _, out var _))
                        dispatchTableSymbols[baseAddr] = $"dtbl_{baseAddr:X8}";
                }

                var baseSym = dispatchTableSymbols != null && dispatchTableSymbols.TryGetValue(baseAddr, out var dt) ? dt :
                    (globalSymbols != null && globalSymbols.TryGetValue(baseAddr, out var gs) ? gs : $"0x{baseAddr:X8}");

                // If the call is through [reg+disp], note it as a secondary deref (often vtbl slot or struct member).
                var callMem = callDisp != 0 ? $"[{callBase}+0x{callDisp:X}]" : $"[{callBase}]";

                // Probe table if it resides in-module; cache per base.
                string tableNote = null;
                if (dispatchTableNotes != null && dispatchTableNotes.TryGetValue(baseAddr, out var cached))
                {
                    tableNote = cached;
                }
                else
                {
                    tableNote = string.Empty;
                    if (objects != null && objBytesByIndex != null && TryMapLinearToObject(objects, baseAddr, out var _, out var _))
                    {
                        var inModule = 0;
                        var samples = 0;
                        var exampleTargets = new List<uint>();
                        for (var k = 0; k < 64; k++)
                        {
                            var entryAddr = unchecked(baseAddr + (uint)(k * 4));
                            if (!TryReadDwordAtLinear(objects, objBytesByIndex, entryAddr, out var val) || val == 0)
                                continue;
                            samples++;
                            if (TryMapLinearToObject(objects, val, out var _, out var _))
                            {
                                inModule++;
                                if (exampleTargets.Count < 4)
                                    exampleTargets.Add(val);
                            }
                        }

                        if (samples > 0)
                        {
                            tableNote = $" ptrs~{inModule}/{samples}";
                            if (exampleTargets.Count > 0)
                                tableNote += $" ex={string.Join(",", exampleTargets.Select(x => $"0x{x:X8}"))}";
                        }
                    }

                    if (dispatchTableNotes != null)
                        dispatchTableNotes[baseAddr] = tableNote;
                }

                // This is best-effort: we don't know the runtime index value.
                return $"DISPATCH?: tbl={baseSym} idx={idxReg} scale={scale}{tableNote} -> {callMem}";
            }

            return string.Empty;
        }

        private static bool TryReadDwordAtLinear(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint addr, out uint value)
        {
            value = 0;
            if (objects == null || objBytesByIndex == null)
                return false;

            if (!TryMapLinearToObject(objects, addr, out var objIndex, out var off))
                return false;

            if (!objBytesByIndex.TryGetValue(objIndex, out var bytes) || bytes == null)
                return false;

            var ioff = (int)off;
            if (ioff < 0 || ioff + 4 > bytes.Length)
                return false;

            value = ReadUInt32(bytes, ioff);
            return true;
        }

        private static bool TryDetectVirtualCallSite(List<Instruction> instructions, int callIdx, out string vtblReg, out uint slot, out string thisReg)
        {
            vtblReg = string.Empty;
            slot = 0;
            thisReg = string.Empty;

            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return false;

            var callText = instructions[callIdx].ToString().Trim();
            var m = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9a-fA-F]+))?\]$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            vtblReg = m.Groups["base"].Value.ToLowerInvariant();
            if (m.Groups["disp"].Success)
                slot = Convert.ToUInt32(m.Groups["disp"].Value, 16);

            // Exclude stack-based indirect calls; those are rarely C++ vtables.
            if (vtblReg == "esp" || vtblReg == "ebp")
                return false;

            // Look back for: mov vtblReg, [thisReg]
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 8; i--)
            {
                var t = instructions[i].ToString().Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                var mm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<src>e[a-z]{2})\]$", RegexOptions.IgnoreCase);
                if (mm.Success)
                {
                    var dst = mm.Groups["dst"].Value.ToLowerInvariant();
                    var src = mm.Groups["src"].Value.ToLowerInvariant();
                    if (dst == vtblReg)
                    {
                        // Avoid treating stack-frame registers as a real "this" pointer.
                        if (src != "esp" && src != "ebp")
                            thisReg = src;
                        break;
                    }
                }
            }

            return true;
        }

        private static bool TryResolveRegisterAsTablePointer(
            List<Instruction> instructions,
            int callIdx,
            string reg,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out uint tablePtr,
            out string source)
        {
            tablePtr = 0;
            source = string.Empty;
            if (instructions == null || callIdx <= 0 || string.IsNullOrEmpty(reg))
                return false;

            // Scan backwards for a defining assignment to the base reg.
            // We mainly want: mov reg, [abs] (global pointer) or mov reg, imm32.
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 16; i--)
            {
                var t = instructions[i].ToString().Trim();

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov reg, 0xXXXXXXXX
                var mi = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*(?<imm>0x[0-9a-fA-F]{{1,8}})$", RegexOptions.IgnoreCase);
                if (mi.Success && TryParseImm32(mi.Groups["imm"].Value, out var imm) && imm != 0)
                {
                    tablePtr = imm;
                    source = "imm";
                    return true;
                }

                // mov reg, [0xXXXXXXXX]
                var ma = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*\[(?<addr>0x[0-9a-fA-F]{{1,8}})\]$", RegexOptions.IgnoreCase);
                if (ma.Success && TryParseImm32(ma.Groups["addr"].Value, out var addr) && addr != 0)
                {
                    if (TryReadDwordAtLinear(objects, objBytesByIndex, addr, out var ptr) && ptr != 0)
                    {
                        tablePtr = ptr;
                        source = $"[{addr:X8}]";
                        return true;
                    }
                    break;
                }

                // lea reg, [0xXXXXXXXX]
                var la = Regex.Match(t, $@"^lea\s+{Regex.Escape(reg)},\s*\[(?<addr>0x[0-9a-fA-F]{{1,8}})\]$", RegexOptions.IgnoreCase);
                if (la.Success && TryParseImm32(la.Groups["addr"].Value, out var leaAddr) && leaAddr != 0)
                {
                    tablePtr = leaAddr;
                    source = "lea";
                    return true;
                }

                // If we see the base register being assigned in some other way, stop.
                // Otherwise we'd risk picking an older (stale) definition and inventing nonsense table pointers.
                if (Regex.IsMatch(t, $@"^(mov|lea)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^(pop|xchg)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^(xor|sub|add|and|or|imul|shl|shr|sar)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase))
                {
                    break;
                }
            }

            return false;
        }

        private static bool TryFindVtableWriteForThis(
            List<Instruction> instructions,
            int callIdx,
            string thisReg,
            List<LEObject> objects,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            out uint vtblAddr)
        {
            vtblAddr = 0;
            if (instructions == null || callIdx <= 0 || string.IsNullOrEmpty(thisReg))
                return false;

            // Typical ctor: mov dword [ecx], 0xXXXXXXXX
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 64; i--)
            {
                var t = instructions[i].ToString().Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    break;

                var m = Regex.Match(t, $@"^mov\s+(?:dword\s+)?\[{Regex.Escape(thisReg)}\],\s*(?<imm>0x[0-9a-fA-F]{{1,8}})$", RegexOptions.IgnoreCase);
                if (m.Success && TryParseImm32(m.Groups["imm"].Value, out var imm))
                {
                    // If the immediate is non-zero, accept it directly.
                    if (imm != 0)
                    {
                        vtblAddr = imm;
                        return true;
                    }

                    // Otherwise, consult fixups for this instruction (common in LE: placeholder imm32 + relocation).
                    var insAddr = (uint)instructions[i].Offset;
                    if (fixupsByInsAddr != null && fixupsByInsAddr.TryGetValue(insAddr, out var fx) && fx != null && fx.Count > 0)
                    {
                        foreach (var f in fx)
                        {
                            // Prefer resolved 32-bit values when available.
                            if (f.Value32.HasValue)
                            {
                                var cand = f.Value32.Value;
                                if (cand != 0 && TryMapLinearToObject(objects, cand, out var _, out var _))
                                {
                                    vtblAddr = cand;
                                    return true;
                                }
                            }

                            // Fallback: use object+offset mapping when present.
                            if (objects != null && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                            {
                                var objIndex = f.TargetObject.Value;
                                if (objIndex >= 1 && objIndex <= objects.Count)
                                {
                                    var cand2 = unchecked(objects[objIndex - 1].BaseAddress + f.TargetOffset.Value);
                                    if (cand2 != 0)
                                    {
                                        vtblAddr = cand2;
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static string TryAnnotateVirtualCallDetailed(
            List<Instruction> instructions,
            int callIdx,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            Dictionary<uint, string> vtblSymbols,
            Dictionary<uint, Dictionary<uint, uint>> vtblSlots)
        {
            if (!TryDetectVirtualCallSite(instructions, callIdx, out var vtblReg, out var slot, out var thisReg))
                return string.Empty;

            // Path A: true C++-style vcall (vtblReg loaded from [thisReg]).
            uint vtblAddr = 0;
            var haveThis = !string.IsNullOrEmpty(thisReg) && IsRegister32(thisReg);
            if (haveThis)
            {
                // Try to infer the concrete vtbl address from a nearby constructor-style write.
                TryFindVtableWriteForThis(instructions, callIdx, thisReg, objects, fixupsByInsAddr, out vtblAddr);
            }

            // Path B: table call where vtblReg is resolved from a recent global/immediate load.
            // This catches patterns like: mov eax, [abs_ptr] ; call [eax+0xC]
            if (vtblAddr == 0)
            {
                if (TryResolveRegisterAsTablePointer(instructions, callIdx, vtblReg, objects, objBytesByIndex, out var tablePtr, out var source))
                {
                    // Only promote it to a named vtable when the pointer is inside the module image.
                    var inModule = TryMapLinearToObject(objects, tablePtr, out var tblObj, out var tblOff);
                    if (!inModule)
                    {
                        // Still emit a useful hint for runtime function tables without polluting the vtable summary.
                        return $"VCALL?: table=0x{tablePtr:X8} (runtime) slot=0x{slot:X} (base={vtblReg} via {source})";
                    }

                    vtblAddr = tablePtr;
                    if (vtblSymbols != null && !vtblSymbols.ContainsKey(vtblAddr))
                        vtblSymbols[vtblAddr] = $"vtbl_{vtblAddr:X8}";

                    uint target2 = 0;
                    if (slot % 4 == 0 && TryReadDwordAtLinear(objects, objBytesByIndex, unchecked(vtblAddr + slot), out var fnPtr2) &&
                        TryMapLinearToObject(objects, fnPtr2, out var fnObj2, out var fnOff2))
                    {
                        var obj2 = objects.FirstOrDefault(o => o.Index == fnObj2);
                        var isExec2 = obj2.Index != 0 && (obj2.Flags & 0x0004) != 0;
                        if (isExec2)
                            target2 = fnPtr2;
                    }

                    if (target2 != 0)
                    {
                        if (vtblSlots != null)
                        {
                            if (!vtblSlots.TryGetValue(vtblAddr, out var slots2))
                                vtblSlots[vtblAddr] = slots2 = new Dictionary<uint, uint>();
                            if (!slots2.ContainsKey(slot))
                                slots2[slot] = target2;
                        }

                        var tableSymResolved = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vsTableResolved) ? vsTableResolved : $"0x{vtblAddr:X8}";
                        return $"VCALL: table={tableSymResolved} slot=0x{slot:X} -> func_{target2:X8} (base={vtblReg} via {source})";
                    }

                    var tableSymUnresolved = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vsTableUnresolved) ? vsTableUnresolved : $"0x{vtblAddr:X8}";
                    return $"VCALL?: table={tableSymUnresolved} slot=0x{slot:X} (base={vtblReg} via {source})";
                }
            }

            // If we still don't have a concrete vtbl address, only emit a soft hint for true vcall sites.
            if (vtblAddr == 0)
            {
                if (!haveThis)
                    return string.Empty;

                var thisHint0 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                return slot != 0
                    ? $"VCALL?: {thisHint0} vtbl=[{thisReg}] slot=0x{slot:X}"
                    : $"VCALL?: {thisHint0} vtbl=[{thisReg}]";
            }

            // Validate vtblAddr is in-module.
            if (!TryMapLinearToObject(objects, vtblAddr, out var vtblObj, out var vtblOff))
            {
                var thisHint1 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                return $"VCALL?: {thisHint1} vtbl=0x{vtblAddr:X8} slot=0x{slot:X}";
            }

            if (vtblSymbols != null && !vtblSymbols.ContainsKey(vtblAddr))
                vtblSymbols[vtblAddr] = $"vtbl_{vtblAddr:X8}";

            uint target = 0;
            if (slot % 4 == 0 && TryReadDwordAtLinear(objects, objBytesByIndex, unchecked(vtblAddr + slot), out var fnPtr) &&
                TryMapLinearToObject(objects, fnPtr, out var fnObj, out var fnOff))
            {
                // Prefer executable targets.
                var obj = objects.FirstOrDefault(o => o.Index == fnObj);
                var isExec = obj.Index != 0 && (obj.Flags & 0x0004) != 0;
                if (isExec)
                    target = fnPtr;
            }

            if (target != 0)
            {
                if (vtblSlots != null)
                {
                    if (!vtblSlots.TryGetValue(vtblAddr, out var slots))
                        vtblSlots[vtblAddr] = slots = new Dictionary<uint, uint>();
                    if (!slots.ContainsKey(slot))
                        slots[slot] = target;
                }

                var thisHint2 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                var vtblSym = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vs) ? vs : $"0x{vtblAddr:X8}";
                return $"VCALL: {thisHint2} vtbl={vtblSym} slot=0x{slot:X} -> func_{target:X8}";
            }

            var thisHint3 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
            var vtblSym2 = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vs2) ? vs2 : $"0x{vtblAddr:X8}";
            return $"VCALL?: {thisHint3} vtbl={vtblSym2} slot=0x{slot:X}";
        }
        private static string TryAnnotateFormatCall(List<Instruction> instructions, int callIdx,
            Dictionary<uint, string> globalSymbols,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> resourceSymbols = null,
            HashSet<uint> resourceGetterTargets = null)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callIns = instructions[callIdx];
            var callText = callIns.ToString();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Collect pushes immediately preceding this call.
            // In cdecl-style code, the format string is often the *last* push before the call.
            var pushedOperands = new List<string>();
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 16; i--)
            {
                var t = instructions[i].ToString();

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                if (t.StartsWith("add esp", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub esp", StringComparison.OrdinalIgnoreCase))
                    break;

                if (!t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                    continue;

                t = RewriteKnownAddressLiterals(t, globalSymbols, stringSymbols, resourceSymbols);
                pushedOperands.Add(t.Substring(5).Trim());
                if (pushedOperands.Count >= 12)
                    break;
            }

            if (pushedOperands.Count == 0)
                return string.Empty;

            // Find any pushed operand that resolves to a known string symbol (prefer a printf-like format).
            string bestSym = string.Empty;
            string bestPreview = string.Empty;
            var bestIsFmt = false;

            for (var k = 0; k < pushedOperands.Count; k++)
            {
                var op = pushedOperands[k];
                if (!TryResolveStringSymFromOperand(instructions, callIdx, op, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var sym, out var preview))
                    continue;

                var isFmt = LooksLikePrintfFormat(preview);
                if (isFmt)
                {
                    bestSym = sym;
                    bestPreview = preview;
                    bestIsFmt = true;
                    break;
                }

                if (string.IsNullOrEmpty(bestSym))
                {
                    bestSym = sym;
                    bestPreview = preview;
                }
            }

            if (string.IsNullOrEmpty(bestSym))
                return string.Empty;

            if (bestIsFmt)
                return $"FMT: printf-like fmt={bestSym} args~{pushedOperands.Count} \"{bestPreview}\"";

            if (!string.IsNullOrEmpty(bestPreview))
                return $"STRCALL: text={bestSym} args~{pushedOperands.Count} \"{bestPreview}\"";

            return $"STRCALL: text={bestSym} args~{pushedOperands.Count}";
        }

        private static string TryAnnotateCallStackCleanup(List<Instruction> instructions, int callIdx)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = instructions[callIdx].ToString();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            if (callIdx + 1 >= instructions.Count)
                return string.Empty;

            var next = instructions[callIdx + 1].ToString().Trim();

            // Common cdecl cleanup: add esp, 0xNN
            var m = Regex.Match(next, @"^add\s+esp,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return string.Empty;

            if (!TryParseImm32(m.Groups["imm"].Value, out var imm))
                return string.Empty;

            if (imm == 0)
                return string.Empty;

            // Heuristic: args are 4-byte pushes
            var argc = (imm % 4 == 0) ? (imm / 4) : 0;
            return argc > 0
                ? $"ARGC: ~{argc} (stack +0x{imm:X})"
                : $"ARGC: stack +0x{imm:X}";
        }

        private static string TryAnnotateVirtualCall(List<Instruction> instructions, int callIdx)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = instructions[callIdx].ToString().Trim();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Looking for an indirect call through a memory operand:
            //   call dword [eax+0xNN]
            //   call [eax+0xNN]
            // Common C++ virtual pattern in 32-bit:
            //   mov vt, [this]
            //   call [vt+slot]
            var m = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?<disp>\+0x[0-9a-fA-F]+)?\]$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return string.Empty;

            var baseReg = m.Groups["base"].Value.ToLowerInvariant();
            var dispHex = m.Groups["disp"].Success ? m.Groups["disp"].Value.Substring(1) : string.Empty; // drop leading '+'
            var slot = 0u;
            var haveSlot = !string.IsNullOrEmpty(dispHex) && TryParseImm32(dispHex, out slot);

            // Look back a short window for: mov baseReg, [thisReg]
            string thisReg = null;
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 6; i--)
            {
                var t = instructions[i].ToString().Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov eax, [ecx]
                var mm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<src>e[a-z]{2})\]$", RegexOptions.IgnoreCase);
                if (mm.Success)
                {
                    var dst = mm.Groups["dst"].Value.ToLowerInvariant();
                    var src = mm.Groups["src"].Value.ToLowerInvariant();
                    if (dst == baseReg)
                    {
                        // Avoid treating stack-frame registers as a real "this" pointer.
                        if (src != "esp" && src != "ebp")
                            thisReg = src;
                        break;
                    }
                }
            }

            // If we couldn't infer a this-reg, still annotate as an indirect call.
            if (string.IsNullOrEmpty(thisReg))
            {
                return haveSlot
                    ? $"VIRT?: call [{baseReg}+0x{slot:X}] (indirect)"
                    : $"VIRT?: call [{baseReg}] (indirect)";
            }

            // Favor C++ thiscall intuition: ECX is often 'this'.
            var thisHint = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
            if (haveSlot)
                return $"VIRT: {thisHint} vtbl=[{thisReg}] slot=0x{slot:X}";
            return $"VIRT: {thisHint} vtbl=[{thisReg}]";
        }

        private static string TryAnnotateResourceStringCall(
            List<Instruction> instructions,
            int callIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> resourceSymbols,
            HashSet<uint> resourceGetterTargets)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;
            if (stringPreview == null)
                return string.Empty;

            var callText = instructions[callIdx].ToString();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // If we detected specific resource-getter call targets, require this call to match.
            if (resourceGetterTargets != null && resourceGetterTargets.Count > 0)
            {
                var mcall = Regex.Match(callText.Trim(), @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (!mcall.Success || !TryParseHexUInt(mcall.Groups["target"].Value, out var tgt) || !resourceGetterTargets.Contains(tgt))
                    return string.Empty;
            }

            // Look back for the common pattern:
            //   mov eax, imm
            //   add edx, 0xE0000 (or lea edx, [reg+0xE0000])
            //   call ...
            // Treat imm as an offset into the region; if (regionBase+imm) matches an s_ symbol, annotate it.
            uint? offsetImm = null;
            uint? regionBase = null;

            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 12; i--)
            {
                var t = instructions[i].ToString().Trim();

                // Stop at control-flow barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                var mo = Regex.Match(t, @"^mov\s+e[a-z]{2},\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (offsetImm == null && mo.Success && TryParseImm32(mo.Groups["imm"].Value, out var oi) && oi < 0x10000)
                {
                    offsetImm = oi;
                    continue;
                }

                var ma = Regex.Match(t, @"^add\s+e[a-z]{2},\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && ma.Success && TryParseImm32(ma.Groups["imm"].Value, out var baseImm) && baseImm >= 0x10000)
                {
                    regionBase = baseImm;
                    continue;
                }

                var ml = Regex.Match(t, @"^lea\s+e[a-z]{2},\s*\[e[a-z]{2}\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
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
                return string.Empty;

            var addr = unchecked(regionBase.Value + offsetImm.Value);
            // Always record a resource symbol for this derived address.
            if (resourceSymbols != null && !resourceSymbols.ContainsKey(addr))
                resourceSymbols[addr] = $"r_{addr:X8}";

            string sym = null;
            var haveStringSym = stringSymbols != null && stringSymbols.TryGetValue(addr, out sym);
            if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var prev) && !string.IsNullOrEmpty(prev))
            {
                var kind = LooksLikePrintfFormat(prev) ? "RESFMT" : "RESSTR";
                var label = haveStringSym ? sym : $"r_{addr:X8}";
                return $"{kind}: {label} \"{prev}\" ; RET=eax=r_{addr:X8}";
            }

            // Still useful: show the derived resource address when it points into a typical resource/string region.
            // (Avoid spamming for small constants or unrelated addresses.)
            var rb = regionBase.Value;
            if (rb >= 0x000C0000 && rb <= 0x000F0000 && (rb % 0x10000 == 0))
                return $"RESOFF: base=0x{rb:X} off=0x{offsetImm.Value:X} => r_{addr:X8} ; RET=eax=r_{addr:X8}";

            return string.Empty;
        }

        private static string TryInlineStringPreview(string insText,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            List<Instruction> instructions,
            int insIdx,
            Dictionary<uint, string> stringSymbols,
            HashSet<uint> resourceGetterTargets)
        {
            if (string.IsNullOrEmpty(insText) || stringPreview == null || stringPreview.Count == 0)
                return string.Empty;

            // Keep this conservative to avoid spam.
            var lower = insText.TrimStart();
            if (!lower.StartsWith("push ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("lea ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("mov ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Fast path: already has an s_XXXXXXXX token
            var sym = ExtractStringSym(insText);
            if (!string.IsNullOrEmpty(sym) && TryParseStringSym(sym, out var addr) &&
                stringPreview.TryGetValue(addr, out var p0) && !string.IsNullOrEmpty(p0))
            {
                return $"STR: \"{p0}\"";
            }

            // Fast path: r_XXXXXXXX token that also points to a known string preview
            var rsym = ExtractResourceSym(insText);
            if (!string.IsNullOrEmpty(rsym) && TryParseResourceSym(rsym, out var raddr) &&
                TryGetStringPreviewAt(raddr, stringPreview, objects, objBytesByIndex, out var rp0) && !string.IsNullOrEmpty(rp0))
            {
                return $"STR: \"{rp0}\"";
            }

            // Heuristic path: try to resolve a computed/pushed register value to a known string address.
            if (instructions == null || insIdx < 0 || insIdx >= instructions.Count)
                return string.Empty;

            var raw = instructions[insIdx].ToString();
            if (TryResolveStringFromInstruction(instructions, insIdx, raw, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var p1))
                return $"STR: \"{p1}\"";

            return string.Empty;
        }

        private static bool TryResolveStringSymFromOperand(
            List<Instruction> instructions,
            int callIdx,
            string operandText,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            HashSet<uint> resourceGetterTargets,
            out string sym,
            out string preview)
        {
            sym = string.Empty;
            preview = string.Empty;

            if (stringSymbols == null || stringSymbols.Count == 0 || stringPreview == null || stringPreview.Count == 0)
                return false;

            if (string.IsNullOrWhiteSpace(operandText))
                return false;

            // Direct s_ token
            var direct = ExtractStringSym(operandText);
            if (!string.IsNullOrEmpty(direct) && TryParseStringSym(direct, out var daddr) &&
                TryGetStringPreviewAt(daddr, stringPreview, objects, objBytesByIndex, out var dp) && !string.IsNullOrEmpty(dp))
            {
                sym = direct;
                preview = dp;
                return true;
            }

            // Direct r_ token (resource-derived). If it points to a known string preview, treat it as a string too.
            var rdirect = ExtractResourceSym(operandText);
            if (!string.IsNullOrEmpty(rdirect) && TryParseResourceSym(rdirect, out var rdaddr) &&
                TryGetStringPreviewAt(rdaddr, stringPreview, objects, objBytesByIndex, out var rdp) && !string.IsNullOrEmpty(rdp))
            {
                sym = rdirect;
                preview = rdp;
                return true;
            }

            // Register operand (e.g. push eax)
            var op = operandText.Trim();
            if (IsRegister32(op) && TryResolveRegisterValueBefore(instructions, callIdx, op, out var raddr, resourceGetterTargets))
            {
                if (TryResolveStringAddressFromRaw(raddr, stringSymbols, out var resolvedAddr, out var resolvedSym) &&
                    TryGetStringPreviewAt(resolvedAddr, stringPreview, objects, objBytesByIndex, out var rp) && !string.IsNullOrEmpty(rp))
                {
                    sym = resolvedSym;
                    preview = rp;
                    return true;
                }
            }

            // Immediate literal (0x...)
            if (TryParseImm32(op, out var imm) && TryResolveStringAddressFromRaw(imm, stringSymbols, out var iaddr, out var isym) &&
                TryGetStringPreviewAt(iaddr, stringPreview, objects, objBytesByIndex, out var ip) && !string.IsNullOrEmpty(ip))
            {
                sym = isym;
                preview = ip;
                return true;
            }

            // Embedded literal (e.g. dword [0x4988])
            var hm = HexLiteralRegex.Match(operandText);
            if (hm.Success && TryParseHexUInt(hm.Value, out var rawLit) &&
                TryResolveStringAddressFromRaw(rawLit, stringSymbols, out var haddr, out var hsym) &&
                TryGetStringPreviewAt(haddr, stringPreview, objects, objBytesByIndex, out var hp) && !string.IsNullOrEmpty(hp))
            {
                sym = hsym;
                preview = hp;
                return true;
            }

            return false;
        }

        private static bool TryResolveStringAddressFromRaw(uint raw, Dictionary<uint, string> stringSymbols, out uint addr, out string sym)
        {
            addr = 0;
            sym = string.Empty;
            if (stringSymbols == null || stringSymbols.Count == 0)
                return false;

            if (stringSymbols.TryGetValue(raw, out sym))
            {
                addr = raw;
                return true;
            }

            // Common DOS4GW convention: strings live in C/D/E/F0000 regions and code references them by 16-bit offsets.
            if (raw < 0x10000)
            {
                foreach (var baseAddr in new[] { 0x000C0000u, 0x000D0000u, 0x000E0000u, 0x000F0000u })
                {
                    var candidate = unchecked(baseAddr + raw);
                    if (stringSymbols.TryGetValue(candidate, out sym))
                    {
                        addr = candidate;
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool TryResolveStringFromInstruction(
            List<Instruction> instructions,
            int insIdx,
            string rawInstruction,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            HashSet<uint> resourceGetterTargets,
            out string preview)
        {
            preview = string.Empty;
            if (stringSymbols == null || stringSymbols.Count == 0 || stringPreview == null || stringPreview.Count == 0)
                return false;
            if (string.IsNullOrWhiteSpace(rawInstruction))
                return false;

            var t = rawInstruction.Trim();

            // push <reg>
            if (t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
            {
                var op = t.Substring(5).Trim();
                if (IsRegister32(op) && TryResolveRegisterValueBefore(instructions, insIdx, op, out var addr, resourceGetterTargets) &&
                    TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                {
                    preview = p;
                    return true;
                }

                if (TryParseImm32(op, out var imm) && TryGetStringPreviewAt(imm, stringPreview, objects, objBytesByIndex, out var p2) && !string.IsNullOrEmpty(p2))
                {
                    preview = p2;
                    return true;
                }
            }

            // mov <reg>, 0x...
            if (t.StartsWith("mov ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = t.Substring(4).Split(',');
                if (parts.Length == 2)
                {
                    var dst = parts[0].Trim();
                    var src = parts[1].Trim();
                    if (IsRegister32(dst) && TryParseImm32(src, out var imm) && TryGetStringPreviewAt(imm, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                    {
                        preview = p;
                        return true;
                    }
                }
            }

            // lea <reg>, [<base>+0x<disp>] where base resolves to a constant
            if (t.StartsWith("lea ", StringComparison.OrdinalIgnoreCase))
            {
                // Example: lea eax, [ebx+0x4e]
                var m = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var baseReg = m.Groups["base"].Value;
                    var disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);
                    if (TryResolveRegisterValueBefore(instructions, insIdx, baseReg, out var baseVal, resourceGetterTargets))
                    {
                        var addr = baseVal + disp;
                        if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                        {
                            preview = p;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static bool TryGetStringPreviewAt(uint addr,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out string preview)
        {
            preview = string.Empty;

            if (stringPreview != null && stringPreview.TryGetValue(addr, out var p0) && !string.IsNullOrEmpty(p0))
            {
                preview = p0;
                return true;
            }

            if (TryReadCStringAtLinear(objects, objBytesByIndex, addr, out var p1))
            {
                preview = p1;
                if (stringPreview != null && !stringPreview.ContainsKey(addr))
                    stringPreview[addr] = p1;
                return true;
            }

            return false;
        }

        private static bool TryReadCStringAtLinear(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint addr, out string preview)
        {
            preview = string.Empty;
            if (objects == null || objBytesByIndex == null)
                return false;

            foreach (var obj in objects)
            {
                if (addr < obj.BaseAddress)
                    continue;
                var end = obj.BaseAddress + obj.VirtualSize;
                if (addr >= end)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes) || bytes == null || bytes.Length == 0)
                    return false;

                var start = (int)(addr - obj.BaseAddress);
                if (start < 0 || start >= bytes.Length)
                    return false;

                var maxLen = Math.Min(bytes.Length, (int)Math.Min(obj.VirtualSize, (uint)bytes.Length));
                if (start >= maxLen)
                    return false;

                var i = start;
                var sb = new StringBuilder();
                while (i < maxLen && IsLikelyStringChar(bytes[i]) && sb.Length < 200)
                {
                    sb.Append((char)bytes[i]);
                    i++;
                }

                var nul = (i < maxLen && bytes[i] == 0x00);
                var s = sb.ToString();
                if (!nul || s.Length < 4)
                    return false;
                if (!LooksLikeHumanString(s))
                    return false;

                preview = EscapeForComment(s);
                return true;
            }

            return false;
        }

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
                var t = instructions[i].ToString().Trim();
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
                var t = instructions[i].ToString().Trim();
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
                var t = instructions[i].ToString().Trim();
                var mcall = Regex.Match(t, @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (!mcall.Success)
                    continue;

                if (!TryParseHexUInt(mcall.Groups["target"].Value, out var tgt))
                    continue;

                uint? id = null;
                uint? baseImm = null;

                for (var k = i - 1; k >= 0 && k >= i - 10; k--)
                {
                    var back = instructions[k].ToString().Trim();
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

        private static string ExtractStringSym(string text)
        {
            if (string.IsNullOrEmpty(text))
                return string.Empty;
            var m = StringSymRegex.Match(text);
            return m.Success ? m.Value : string.Empty;
        }

        private static bool TryParseStringSym(string sym, out uint addr)
        {
            addr = 0;
            if (string.IsNullOrEmpty(sym) || sym.Length != 10 || !sym.StartsWith("s_", StringComparison.OrdinalIgnoreCase))
                return false;
            return uint.TryParse(sym.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out addr);
        }

        private static string ExtractResourceSym(string text)
        {
            if (string.IsNullOrEmpty(text))
                return string.Empty;
            var m = ResourceSymRegex.Match(text);
            return m.Success ? m.Value : string.Empty;
        }

        private static bool TryParseResourceSym(string sym, out uint addr)
        {
            addr = 0;
            if (string.IsNullOrEmpty(sym) || sym.Length != 10 || !sym.StartsWith("r_", StringComparison.OrdinalIgnoreCase))
                return false;
            return uint.TryParse(sym.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out addr);
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

        private static List<LEFixup> GetFixupsForInstruction(List<LEFixup> fixups, Instruction ins, ref int idx)
        {
            if (fixups == null || fixups.Count == 0 || ins == null)
                return new List<LEFixup>(0);

            var insStart = (uint)ins.Offset;
            var insEnd = unchecked((uint)(insStart + (uint)ins.Length));

            // Advance past fixups that are below this instruction.
            while (idx < fixups.Count && fixups[idx].SiteLinear < insStart)
                idx++;

            if (idx >= fixups.Count)
                return new List<LEFixup>(0);

            var hit = new List<LEFixup>();
            var scan = idx;
            while (scan < fixups.Count)
            {
                var f = fixups[scan];
                if (f.SiteLinear >= insEnd)
                    break;
                hit.Add(f);
                scan++;
            }

            return hit;
        }

        private static string FormatFixupAnnotation(Instruction ins, List<LEFixup> fixupsHere)
        {
            if (fixupsHere == null || fixupsHere.Count == 0 || ins == null)
                return string.Empty;

            var insStart = (uint)ins.Offset;
            var parts = new List<string>();

            foreach (var f in fixupsHere)
            {
                var delta = unchecked((int)(f.SiteLinear - insStart));
                var kind = TryClassifyFixupKind(ins, delta, out var k) ? k : "unk";

                var mapped = (f.TargetObject.HasValue && f.TargetOffset.HasValue)
                    ? $" => obj{f.TargetObject.Value}+0x{f.TargetOffset.Value:X}"
                    : string.Empty;

                var v32 = f.Value32.HasValue ? $" val32=0x{f.Value32.Value:X8}" : string.Empty;

                parts.Add($"{kind} site+{delta} type=0x{f.Type:X2} flags=0x{f.Flags:X2}{v32}{mapped}");
            }

            if (parts.Count == 0)
                return string.Empty;

            var distinct = parts.Distinct().ToList();
            const int maxShown = 3;
            if (distinct.Count <= maxShown)
                return string.Join(" | ", distinct);

            return string.Join(" | ", distinct.Take(maxShown)) + $" | (+{distinct.Count - maxShown} more)";
        }

        private static bool TryClassifyFixupKind(Instruction ins, int fixupDelta, out string kind)
        {
            kind = string.Empty;

            if (ins?.Bytes == null || ins.Bytes.Length == 0)
                return false;
            if (fixupDelta < 0 || fixupDelta >= ins.Bytes.Length)
                return false;

            var b = ins.Bytes;

            // Skip common prefixes
            var p = 0;
            while (p < b.Length)
            {
                var x = b[p];
                // operand-size, address-size, rep/lock, segment overrides
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65)
                {
                    p++;
                    continue;
                }
                break;
            }

            if (p >= b.Length)
                return false;

            var op0 = b[p];

            // MOV moffs: A0-A3 (disp32 right after opcode in 32-bit addr mode)
            if (op0 >= 0xA0 && op0 <= 0xA3)
            {
                var dispOff = p + 1;
                if (fixupDelta == dispOff)
                {
                    kind = "disp32";
                    return true;
                }
            }

            // Two-byte opcodes
            var opLen = 1;
            byte op1 = 0;
            if (op0 == 0x0F)
            {
                if (p + 1 >= b.Length)
                    return false;
                op1 = b[p + 1];
                opLen = 2;
            }

            var opIndexEnd = p + opLen;
            if (opIndexEnd >= b.Length)
                return false;

            // Patterns with ModRM + disp32 + immediate (very common in DOS4GW code)
            // 80/81/83 grp1, C6/C7 mov r/m, imm
            if (op0 == 0x80 || op0 == 0x81 || op0 == 0x83 || op0 == 0xC6 || op0 == 0xC7)
            {
                var modrmIndex = opIndexEnd;
                var modrm = b[modrmIndex];
                var mod = (modrm >> 6) & 0x3;
                var rm = modrm & 0x7;

                // Only handle the simple disp32 form: mod=00 rm=101 (no SIB)
                if (mod == 0 && rm == 5)
                {
                    var dispOff = modrmIndex + 1;
                    var afterDisp = dispOff + 4;

                    if (fixupDelta == dispOff)
                    {
                        kind = "disp32";
                        return true;
                    }

                    // Immediate offset depends on opcode.
                    if (op0 == 0x81 || op0 == 0xC7)
                    {
                        if (fixupDelta == afterDisp)
                        {
                            kind = "imm32";
                            return true;
                        }
                    }
                    else if (op0 == 0x80 || op0 == 0x83 || op0 == 0xC6)
                    {
                        if (fixupDelta == afterDisp)
                        {
                            kind = "imm8";
                            return true;
                        }
                    }
                }
            }

            // Common reg/mem ops with disp32 only (no immediate): 8B/89/8D, etc.
            if (op0 == 0x8B || op0 == 0x89 || op0 == 0x8D)
            {
                var modrmIndex = opIndexEnd;
                if (modrmIndex < b.Length)
                {
                    var modrm = b[modrmIndex];
                    var mod = (modrm >> 6) & 0x3;
                    var rm = modrm & 0x7;
                    if (mod == 0 && rm == 5)
                    {
                        var dispOff = modrmIndex + 1;
                        if (fixupDelta == dispOff)
                        {
                            kind = "disp32";
                            return true;
                        }
                    }
                }
            }

            // Fallback heuristic: if fixup hits the last 4 bytes, it’s likely an imm32 or disp32.
            if (ins.Bytes.Length >= 4 && fixupDelta == ins.Bytes.Length - 4)
            {
                kind = "imm32?";
                return true;
            }

            return false;
        }

        private static ulong ComputeEntryLinear(LEHeader header, List<LEObject> objects)
        {
            if (header.EntryEipObject == 0)
                return 0;

            var obj = objects.Find(o => o.Index == header.EntryEipObject);
            return obj.BaseAddress + header.EntryEip;
        }

        private static bool TryFindLEHeaderOffset(byte[] fileBytes, out int offset)
        {
            // Prefer the canonical LE signature + byte/word order fields.
            // For DOS4GW-produced LEs this tends to be unique.
            for (var i = 0; i <= fileBytes.Length - 4; i++)
            {
                if (fileBytes[i] == (byte)'L' && fileBytes[i + 1] == (byte)'E' && fileBytes[i + 2] == 0x00 &&
                    fileBytes[i + 3] == 0x00)
                {
                    offset = i;
                    return true;
                }
            }

            offset = 0;
            return false;
        }

        private static bool TryParseHeader(byte[] fileBytes, int headerOffset, out LEHeader header, out string error)
        {
            header = default;
            error = string.Empty;

            if (headerOffset < 0 || headerOffset + 0x84 >= fileBytes.Length)
            {
                error = "Invalid LE header offset";
                return false;
            }

            if (fileBytes[headerOffset] != (byte)'L' || fileBytes[headerOffset + 1] != (byte)'E')
            {
                error = "Invalid LE signature";
                return false;
            }

            // byte order + word order are 0 for little endian
            var byteOrder = ReadUInt16(fileBytes, headerOffset + 0x02);
            var wordOrder = ReadUInt16(fileBytes, headerOffset + 0x04);
            if (byteOrder != 0 || wordOrder != 0)
            {
                error = "Unsupported LE byte/word order";
                return false;
            }

            header.HeaderOffset = headerOffset;

            header.ModuleFlags = ReadUInt32(fileBytes, headerOffset + 0x10);
            header.NumberOfPages = ReadUInt32(fileBytes, headerOffset + 0x14);
            header.EntryEipObject = ReadUInt32(fileBytes, headerOffset + 0x18);
            header.EntryEip = ReadUInt32(fileBytes, headerOffset + 0x1C);
            header.EntryEspObject = ReadUInt32(fileBytes, headerOffset + 0x20);
            header.EntryEsp = ReadUInt32(fileBytes, headerOffset + 0x24);
            header.PageSize = ReadUInt32(fileBytes, headerOffset + 0x28);
            header.LastPageSize = ReadUInt32(fileBytes, headerOffset + 0x2C);

            header.ObjectTableOffset = ReadUInt32(fileBytes, headerOffset + 0x40);
            header.ObjectCount = ReadUInt32(fileBytes, headerOffset + 0x44);
            header.ObjectPageMapOffset = ReadUInt32(fileBytes, headerOffset + 0x48);

            header.FixupPageTableOffset = ReadUInt32(fileBytes, headerOffset + 0x68);
            header.FixupRecordTableOffset = ReadUInt32(fileBytes, headerOffset + 0x6C);

            // Best-effort: import tables (offsets are relative to LE header)
            header.ImportModuleTableOffset = ReadUInt32(fileBytes, headerOffset + 0x70);
            header.ImportModuleTableEntries = ReadUInt32(fileBytes, headerOffset + 0x74);
            header.ImportProcTableOffset = ReadUInt32(fileBytes, headerOffset + 0x78);

            header.DataPagesOffset = ReadUInt32(fileBytes, headerOffset + 0x80);

            if (header.PageSize == 0 || header.ObjectCount == 0 || header.NumberOfPages == 0)
            {
                error = "Invalid LE header (zero PageSize/ObjectCount/PageCount)";
                return false;
            }

            // If last page size is 0, treat it as full page size per spec conventions.
            if (header.LastPageSize == 0)
                header.LastPageSize = header.PageSize;

            _logger.Info($"Detected LE header at 0x{headerOffset:X} (Objects={header.ObjectCount}, Pages={header.NumberOfPages}, PageSize={header.PageSize})");
            return true;
        }

        private static List<string> TryParseImportModules(byte[] fileBytes, LEHeader header)
        {
            try
            {
                if (header.ImportModuleTableOffset == 0 || header.ImportModuleTableEntries == 0)
                    return null;

                var start = header.HeaderOffset + (int)header.ImportModuleTableOffset;
                if (start < 0 || start >= fileBytes.Length)
                    return null;

                var modules = new List<string>((int)Math.Min(header.ImportModuleTableEntries, 4096));
                var off = start;
                for (var i = 0; i < header.ImportModuleTableEntries; i++)
                {
                    if (off >= fileBytes.Length)
                        break;
                    var len = fileBytes[off];
                    off++;
                    if (len == 0)
                    {
                        modules.Add(string.Empty);
                        continue;
                    }
                    if (off + len > fileBytes.Length)
                        break;
                    var name = Encoding.ASCII.GetString(fileBytes, off, len);
                    modules.Add(name);
                    off += len;
                }

                return modules;
            }
            catch
            {
                return null;
            }
        }

        private static string TryReadImportProcName(byte[] fileBytes, LEHeader header, uint procNameOffset)
        {
            try
            {
                if (header.ImportProcTableOffset == 0)
                    return string.Empty;

                var baseOff = header.HeaderOffset + (int)header.ImportProcTableOffset;
                var off = baseOff + (int)procNameOffset;
                if (off < 0 || off >= fileBytes.Length)
                    return string.Empty;
                var len = fileBytes[off];
                off++;
                if (len == 0)
                    return string.Empty;
                if (off + len > fileBytes.Length)
                    return string.Empty;
                return Encoding.ASCII.GetString(fileBytes, off, len);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool TryGetFixupStreams(byte[] fileBytes, LEHeader header, out uint[] fixupPageOffsets, out byte[] fixupRecordStream)
        {
            fixupPageOffsets = null;
            fixupRecordStream = null;

            try
            {
                if (header.FixupPageTableOffset == 0 || header.FixupRecordTableOffset == 0 || header.NumberOfPages == 0)
                    return false;

                var pageTableStart = header.HeaderOffset + (int)header.FixupPageTableOffset;
                var recordStart = header.HeaderOffset + (int)header.FixupRecordTableOffset;
                if (pageTableStart < 0 || pageTableStart >= fileBytes.Length)
                    return false;
                if (recordStart < 0 || recordStart >= fileBytes.Length)
                    return false;

                var count = checked((int)header.NumberOfPages + 1);
                var offsets = new uint[count];
                for (var i = 0; i < count; i++)
                {
                    var off = pageTableStart + i * 4;
                    if (off + 4 > fileBytes.Length)
                        return false;
                    offsets[i] = ReadUInt32(fileBytes, off);
                }

                var total = offsets[count - 1];
                if (total == 0)
                    return false;
                if (recordStart + total > fileBytes.Length)
                    total = (uint)Math.Max(0, fileBytes.Length - recordStart);

                var records = new byte[total];
                Buffer.BlockCopy(fileBytes, recordStart, records, 0, (int)total);

                fixupPageOffsets = offsets;
                fixupRecordStream = records;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static List<LEFixup> ParseFixupsForWindow(
            LEHeader header,
            List<LEObject> objects,
            uint[] pageMap,
            List<string> importModules,
            byte[] fileBytes,
            uint[] fixupPageOffsets,
            byte[] fixupRecordStream,
            byte[] objBytes,
            LEObject obj,
            uint startLinear,
            uint endLinear)
        {
            // DOS4GW/MS-DOS focused fixup decoder.
            // Empirically, many DOS4GW LEs use a fixed record stride per page (often 8/10/12/16).
            // We use the stride-guessing logic to parse records consistently and then enrich by
            // reading the value at the fixup site and mapping it to an object+offset when it looks
            // like an internal pointer.
            var fixups = new List<LEFixup>();

            if (objBytes == null || objBytes.Length == 0)
                return fixups;

            for (var i = 0; i < obj.PageCount; i++)
            {
                // IMPORTANT: Fixup page table is indexed by the logical page-map entry index,
                // not the physical page number.
                var logicalPageIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (logicalPageIndex0 < 0 || logicalPageIndex0 >= pageMap.Length)
                    break;

                var logicalPageNumber1 = (uint)(logicalPageIndex0 + 1);
                if (logicalPageNumber1 == 0 || logicalPageNumber1 > header.NumberOfPages)
                    continue;

                var physicalPage = pageMap[logicalPageIndex0]; // may be 0
                var pageLinearBase = unchecked(obj.BaseAddress + (uint)(i * header.PageSize));

                // quick window reject
                var pageLinearEnd = unchecked(pageLinearBase + header.PageSize);
                if (pageLinearEnd <= startLinear || pageLinearBase >= endLinear)
                    continue;

                var pageIndex0 = (int)(logicalPageNumber1 - 1);
                if (pageIndex0 < 0 || pageIndex0 + 1 >= fixupPageOffsets.Length)
                    continue;

                var recStart = fixupPageOffsets[pageIndex0];
                var recEnd = fixupPageOffsets[pageIndex0 + 1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                var len = (int)(recEnd - recStart);
                var guess = GuessStride(fixupRecordStream, (int)recStart, len, (int)header.PageSize);
                var stride = guess.Stride;
                if (stride <= 0)
                    stride = 16;

                var entries = len / stride;
                if (entries <= 0)
                    continue;

                // Keep a reasonable cap to avoid pathological pages.
                entries = Math.Min(entries, 4096);

                for (var entry = 0; entry < entries; entry++)
                {
                    var p = (int)recStart + entry * stride;
                    if (p + 4 > (int)recEnd)
                        break;

                    var srcType = fixupRecordStream[p + 0];
                    var flags = fixupRecordStream[p + 1];
                    var srcOff = (ushort)(fixupRecordStream[p + 2] | (fixupRecordStream[p + 3] << 8));
                    var sourceLinear = unchecked(pageLinearBase + srcOff);

                    // Best-effort: read value at/near fixup site from reconstructed object bytes.
                    // Some DOS4GW records appear to point slightly before the relocated field; probing
                    // a few bytes forward greatly reduces false positives (e.g., reading opcode bytes).
                    var objOffset = (int)((uint)i * header.PageSize + srcOff);
                    uint? value32 = null;
                    ushort? value16 = null;
                    int chosenDelta = 0;
                    int? mappedObj = null;
                    uint mappedOff = 0;

                    if (objOffset >= 0)
                    {
                        // Recover small object-relative offsets first (common for DOS4GW resource/string regions like 0xE0000+off).
                        // This avoids accidentally treating opcode+imm byte sequences as in-module pointers.
                        for (var delta = -3; delta <= 3; delta++)
                        {
                            var off = objOffset + delta;
                            if (off < 0)
                                continue;
                            if (off + 4 > objBytes.Length)
                                continue;
                            var v = ReadUInt32(objBytes, off);
                            if (v != 0 && v < 0x10000)
                            {
                                value32 = v;
                                chosenDelta = delta;
                                break;
                            }
                        }

                        // If no small offset candidate, try to find a 32-bit in-module pointer near the fixup site.
                        // Some records point into the middle of an imm32/disp32 field, so probe both backward and forward.
                        if (!value32.HasValue)
                        {
                            for (var delta = -3; delta <= 3; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0)
                                    continue;
                                if (off + 4 > objBytes.Length)
                                    continue;
                                var v = ReadUInt32(objBytes, off);
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff))
                                {
                                    value32 = v;
                                    chosenDelta = delta;
                                    mappedObj = tobj;
                                    mappedOff = toff;
                                    break;
                                }
                            }
                        }

                        // If no mapped pointer found, read the raw dword/word at the original site.
                        if (!value32.HasValue)
                        {
                            if (objOffset + 4 <= objBytes.Length)
                                value32 = ReadUInt32(objBytes, objOffset);
                            else if (objOffset + 2 <= objBytes.Length)
                                value16 = ReadUInt16(objBytes, objOffset);
                        }
                    }

                    // For DOS4GW/MS-DOS game workflows we mostly care about internal pointers.
                    // If we couldn't map a 32-bit value into a known object, it often represents
                    // opcode bytes or plain constants. However, DOS4GW fixups frequently also
                    // carry small object-relative offsets (e.g., into a C/D/E/F0000 string/resource region).
                    if (value32.HasValue && !mappedObj.HasValue && value32.Value >= 0x10000)
                        value32 = null;

                    var desc = $"type=0x{srcType:X2} flags=0x{flags:X2} stride={stride}";

                    if (value32.HasValue)
                    {
                        if (mappedObj.HasValue)
                        {
                            desc += $" site+{chosenDelta} val32=0x{value32.Value:X8} => obj{mappedObj.Value}+0x{mappedOff:X}";
                        }
                        else
                        {
                            // Still useful to print the value when it looks like an in-module linear address.
                            desc += $" val32=0x{value32.Value:X8}";
                        }
                    }
                    else if (value16.HasValue)
                    {
                        desc += $" val16=0x{value16.Value:X4}";
                    }

                    // (Optional) try to interpret import module/proc table if present.
                    // Many DOS4GW games have ImportModuleTableEntries=0, so this often won't apply.
                    if (importModules != null && importModules.Count > 0 && stride >= 10)
                    {
                        // Try a lightweight hint: treat next 2 bytes as module index and next 4 as name offset.
                        if (p + 10 <= (int)recEnd)
                        {
                            var mod = (ushort)(fixupRecordStream[p + 4] | (fixupRecordStream[p + 5] << 8));
                            var procOff = ReadUInt32(fixupRecordStream, p + 6);
                            if (mod > 0 && mod <= importModules.Count)
                            {
                                var modName = importModules[mod - 1];
                                var procName = TryReadImportProcName(fileBytes, header, procOff);
                                if (!string.IsNullOrEmpty(modName) && !string.IsNullOrEmpty(procName))
                                    desc += $" import={modName}!{procName}";
                                else if (!string.IsNullOrEmpty(modName))
                                    desc += $" import={modName}!@0x{procOff:X}";
                            }
                        }
                    }

                    // Only keep fixups within the current disassembly window.
                    if (sourceLinear >= startLinear && sourceLinear < endLinear)
                    {
                        var siteLinear = unchecked(sourceLinear + (uint)chosenDelta);
                        fixups.Add(new LEFixup
                        {
                            SourceLinear = sourceLinear,
                            SourceOffsetInPage = srcOff,
                            PageNumber = physicalPage,
                            SiteLinear = siteLinear,
                            SiteDelta = (byte)Math.Min(255, Math.Max(0, chosenDelta)),
                            Value32 = value32,
                            TargetObject = mappedObj,
                            TargetOffset = mappedObj.HasValue ? (uint?)mappedOff : null,
                            Type = srcType,
                            Flags = flags
                        });
                    }
                }
            }

            return fixups;
        }

        private static bool TryMapLinearToObject(List<LEObject> objects, uint linear, out int objIndex, out uint offset)
        {
            objIndex = 0;
            offset = 0;

            if (objects == null || objects.Count == 0)
                return false;

            // Objects are typically few (here: 3), so linear scan is fine.
            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0)
                    continue;

                // Allow a small slack for references that land in padding past VirtualSize.
                var end = unchecked(obj.BaseAddress + obj.VirtualSize + 0x1000);
                if (linear >= obj.BaseAddress && linear < end)
                {
                    objIndex = obj.Index;
                    offset = unchecked(linear - obj.BaseAddress);
                    return true;
                }
            }

            return false;
        }

        private static List<LEObject> ParseObjects(byte[] fileBytes, LEHeader header)
        {
            var objects = new List<LEObject>((int)header.ObjectCount);

            var objectTableStart = header.HeaderOffset + (int)header.ObjectTableOffset;
            for (var i = 0; i < header.ObjectCount; i++)
            {
                var entryOffset = objectTableStart + i * LE_OBJECT_ENTRY_SIZE;
                if (entryOffset + LE_OBJECT_ENTRY_SIZE > fileBytes.Length)
                    break;

                // LE object entry is 6x uint32
                var virtualSize = ReadUInt32(fileBytes, entryOffset + 0x00);
                var baseAddress = ReadUInt32(fileBytes, entryOffset + 0x04);
                var flags = ReadUInt32(fileBytes, entryOffset + 0x08);
                var pageMapIndex = ReadUInt32(fileBytes, entryOffset + 0x0C);
                var pageCount = ReadUInt32(fileBytes, entryOffset + 0x10);

                objects.Add(new LEObject
                {
                    Index = i + 1,
                    VirtualSize = virtualSize,
                    BaseAddress = baseAddress,
                    Flags = flags,
                    PageMapIndex = pageMapIndex,
                    PageCount = pageCount
                });
            }

            return objects;
        }

        private static uint[] ParseObjectPageMap(byte[] fileBytes, LEHeader header)
        {
            var pageMapStart = header.HeaderOffset + (int)header.ObjectPageMapOffset;
            var map = new uint[header.NumberOfPages];

            for (var i = 0; i < map.Length; i++)
            {
                var off = pageMapStart + i * 4;
                if (off + 4 > fileBytes.Length)
                    break;

                // LE object page map entries are 4 bytes.
                // For DOS4GW-style LEs, the physical page number is stored as a 16-bit value in the upper word.
                // (The lower word is typically flags.)
                map[i] = ReadUInt16(fileBytes, off + 2);
            }

            return map;
        }

        private static byte[] ReconstructObjectBytes(byte[] fileBytes, LEHeader header, uint[] pageMap, int dataPagesBase, LEObject obj)
        {
            var pageSize = (int)header.PageSize;
            var totalLen = checked((int)obj.PageCount * pageSize);
            var buf = new byte[totalLen];

            for (var i = 0; i < obj.PageCount; i++)
            {
                var pageMapIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (pageMapIndex0 < 0 || pageMapIndex0 >= pageMap.Length)
                    break;

                var physicalPage = pageMap[pageMapIndex0]; // 1-based
                if (physicalPage == 0)
                    continue;

                var isLastModulePage = physicalPage == header.NumberOfPages;
                var bytesThisPage = isLastModulePage ? (int)header.LastPageSize : pageSize;

                var pageFileOffset = dataPagesBase + (int)(physicalPage - 1) * pageSize;
                if (pageFileOffset < 0 || pageFileOffset >= fileBytes.Length)
                    break;

                var available = Math.Min(bytesThisPage, fileBytes.Length - pageFileOffset);
                if (available <= 0)
                    break;

                Buffer.BlockCopy(fileBytes, pageFileOffset, buf, i * pageSize, available);
            }

            return buf;
        }

        private static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)(data[offset] |
                          (data[offset + 1] << 8) |
                          (data[offset + 2] << 16) |
                          (data[offset + 3] << 24));
        }

        private static string HexDump(byte[] data, int offset, int length, int bytesPerLine = 16)
        {
            if (data == null || length <= 0)
                return string.Empty;

            var sb = new StringBuilder();
            var end = Math.Min(data.Length, offset + length);
            for (var i = offset; i < end; i += bytesPerLine)
            {
                var lineLen = Math.Min(bytesPerLine, end - i);
                sb.Append(";   ");
                sb.Append($"0x{(i - offset):X4}: ");
                for (var j = 0; j < lineLen; j++)
                {
                    sb.Append(data[i + j].ToString("X2"));
                    if (j + 1 < lineLen)
                        sb.Append(' ');
                }
                sb.AppendLine();
            }
            return sb.ToString().TrimEnd();
        }

        private static bool TryGetRelativeBranchTarget(Instruction ins, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            if (ins == null || ins.Bytes == null || ins.Bytes.Length < 2)
                return false;

            // CALL rel32: E8 xx xx xx xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Icall && ins.Bytes[0] == 0xE8 && ins.Bytes.Length >= 5)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 1);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                isCall = true;
                return true;
            }

            // JMP rel32: E9 xx xx xx xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ijmp && ins.Bytes[0] == 0xE9 && ins.Bytes.Length >= 5)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 1);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // JMP rel8: EB xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ijmp && ins.Bytes[0] == 0xEB && ins.Bytes.Length >= 2)
            {
                var rel = unchecked((sbyte)ins.Bytes[1]);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // Jcc rel8: 70-7F xx
            if (MnemonicGroupings.JumpGroup.Contains(ins.Mnemonic) && ins.Bytes[0] >= 0x70 && ins.Bytes[0] <= 0x7F &&
                ins.Bytes.Length >= 2)
            {
                var rel = unchecked((sbyte)ins.Bytes[1]);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // Jcc rel32: 0F 80-8F xx xx xx xx
            if (MnemonicGroupings.JumpGroup.Contains(ins.Mnemonic) && ins.Bytes[0] == 0x0F && ins.Bytes.Length >= 6 &&
                ins.Bytes[1] >= 0x80 && ins.Bytes[1] <= 0x8F)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 2);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            return false;
        }
    }
}
