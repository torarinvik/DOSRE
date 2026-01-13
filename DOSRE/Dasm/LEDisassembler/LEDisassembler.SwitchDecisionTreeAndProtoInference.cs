using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
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
            if (!TryParseCmpReg8Imm8(InsText(instructions[startIdx]), out _, out _))
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

                var a = InsText(instructions[i]);
                if (!TryParseCmpReg8Imm8(a, out var r8, out _))
                    continue;

                if (!IsEqualityJumpMnemonic(InsText(instructions[i + 1])))
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
                var a = InsText(instructions[i]);
                if (!TryParseCmpReg8Imm8(a, out var r8, out var imm8))
                    continue;

                if (reg == null)
                    reg = r8;
                else if (!reg.Equals(r8, StringComparison.OrdinalIgnoreCase))
                    continue;

                var b = instructions[i + 1];
                if (!IsEqualityJumpMnemonic(InsText(b)))
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
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
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

        private static void CollectLocalBitWidthHintsForFunction(
            string[] cookedByIndex,
            int startIdx,
            int endIdx,
            out Dictionary<string, int> bitsByLocal)
        {
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (cookedByIndex == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(cookedByIndex.Length, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i] ?? string.Empty;
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

            var t = InsText(instructions[idx]).Trim();

            // Classic: push ebp; mov ebp, esp
            if (t.Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase))
            {
                var back = Math.Max(0, idx - 4);
                for (var i = back; i < idx; i++)
                {
                    if (InsText(instructions[i]).Trim().Equals("push ebp", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            // Less common, but still a clear frame setup.
            if (t.StartsWith("enter ", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        // Decode heuristic: linear sweep disassembly can be thrown off by a single 0x00 byte of
        // padding immediately after a RET/RETF/IRET. Opcode 0x00 consumes the next byte (ModRM),
        // which means the true entrypoint at the next byte becomes "inside" a decoded instruction.
        //
        // To avoid that class of 1-byte misalignment, normalize a short run of 0x00 bytes
        // immediately after return instructions to 0x90 (NOP) for decoding only.
        // The caller can track `normalizedByteAddrs` and render them as `db 0x00`.
        internal static int NormalizePostRetZeroPaddingToNops(
            byte[] code,
            uint baseAddress,
            HashSet<uint> normalizedByteAddrs,
            int maxRun = 32)
        {
            if (code == null || code.Length == 0 || maxRun <= 0)
                return 0;

            var normalized = 0;

            for (var i = 0; i < code.Length; i++)
            {
                var b = code[i];
                var retLen = b switch
                {
                    0xC3 => 1, // ret
                    0xCB => 1, // retf
                    0xCF => 1, // iret
                    0xC2 => 3, // ret imm16
                    0xCA => 3, // retf imm16
                    _ => 0,
                };

                if (retLen == 0)
                    continue;

                var j = i + retLen;
                var run = 0;
                while (j < code.Length && run < maxRun && code[j] == 0x00)
                {
                    code[j] = 0x90; // nop (decode-only)
                    normalizedByteAddrs?.Add(baseAddress + (uint)j);
                    normalized++;
                    run++;
                    j++;
                }

                // Continue scanning from the end of the run to avoid O(n^2) on large padding.
                if (j > i)
                    i = j - 1;
            }

            return normalized;
        }

        internal static int RefineFunctionStartsByPrologAfterRet(List<Instruction> instructions, HashSet<uint> functionStarts)
        {
            if (instructions == null || instructions.Count < 4 || functionStarts == null)
                return 0;

            static bool IsPadding(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;
                t = t.Trim();
                return t.Equals("nop", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("int3", StringComparison.OrdinalIgnoreCase);
            }

            static bool IsRet(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().StartsWith("ret", StringComparison.OrdinalIgnoreCase);

            static bool IsPushEbp(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().Equals("push ebp", StringComparison.OrdinalIgnoreCase);

            static bool IsLeadingPush(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;
                t = t.Trim();
                return t.Equals("push ebx", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("push ecx", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("push edx", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("push esi", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("push edi", StringComparison.OrdinalIgnoreCase);
            }

            static bool IsMovEbpEsp(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase);

            static bool IsEnter(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().StartsWith("enter ", StringComparison.OrdinalIgnoreCase);

            var added = 0;
            for (var i = 0; i < instructions.Count - 1; i++)
            {
                var ti = InsText(instructions[i]);
                if (!IsRet(ti))
                    continue;

                var j = i + 1;
                while (j < instructions.Count)
                {
                    var tj = InsText(instructions[j]);
                    if (!IsPadding(tj))
                        break;
                    j++;
                }

                if (j >= instructions.Count)
                    break;

                var t0 = InsText(instructions[j]);
                uint start = 0;
                var ok = false;

                if (IsEnter(t0))
                {
                    start = (uint)instructions[j].Offset;
                    ok = true;
                }
                else
                {
                    // Accept optional leading pushes of saved regs before the classic frame setup.
                    // Example:
                    //   push ebx; push ecx; push edx; push esi; push edi; push ebp; mov ebp, esp
                    var k = j;
                    var pushed = 0;
                    while (k < instructions.Count && pushed < 8)
                    {
                        var tk = InsText(instructions[k]);
                        if (!IsLeadingPush(tk))
                            break;
                        k++;
                        pushed++;
                    }

                    if (k < instructions.Count && IsPushEbp(InsText(instructions[k])) && k + 1 < instructions.Count)
                    {
                        var t1 = InsText(instructions[k + 1]);
                        if (IsMovEbpEsp(t1))
                        {
                            start = (uint)instructions[j].Offset;
                            ok = true;
                        }
                    }

                    // Also keep the previous strict pattern for completeness.
                    if (!ok && IsPushEbp(t0) && j + 1 < instructions.Count)
                    {
                        var t1 = InsText(instructions[j + 1]);
                        if (IsMovEbpEsp(t1))
                        {
                            start = (uint)instructions[j].Offset;
                            ok = true;
                        }
                    }
                }

                if (!ok)
                    continue;

                if (!functionStarts.Contains(start))
                {
                    functionStarts.Add(start);
                    added++;
                }
            }

            return added;
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
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));

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
                var raw = InsText(instructions[i]);
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
                    var prev = RewriteStackFrameOperands(InsText(instructions[j]));
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

        private static void InferProtoHintsForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredOutAliases,
            out List<string> outAliasHints,
            out Dictionary<string, int> bitsByLocal,
            out int argCount,
            out string cc,
            out int? retImmBytes)
        {
            inferredOutAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            outAliasHints = new List<string>();
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            argCount = 0;
            cc = null;
            retImmBytes = null;

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Out-param alias tracking.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Track pushes in a small sliding window before calls.
            var pushRegCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var pushWindow = new Queue<string>();
            const int pushWindowSize = 12;

            // Args usage.
            var usedArgMax = -1;

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
                var t = cooked.Trim();

                // Update arg usage (fast scan for arg_N).
                var pos = 0;
                while (pos < t.Length)
                {
                    pos = t.IndexOf("arg_", pos, StringComparison.OrdinalIgnoreCase);
                    if (pos < 0)
                        break;
                    var j = pos + 4;
                    var n = 0;
                    var any = false;
                    while (j < t.Length)
                    {
                        var ch = t[j];
                        if (ch < '0' || ch > '9')
                            break;
                        any = true;
                        n = (n * 10) + (ch - '0');
                        if (n > 4096)
                            break;
                        j++;
                    }
                    if (any)
                        usedArgMax = Math.Max(usedArgMax, n);
                    pos = j;
                }

                // Bit width hints (locals).
                var m = Regex.Match(t, @"^mov\s+\[(?<local>local_[0-9A-Fa-f]+)\]\s*,\s*(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\b", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                }
                else
                {
                    m = Regex.Match(t, @"^mov\s+(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\s*,\s*\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        var bits = GetRegBitWidth(m.Groups["reg"].Value);
                        if (bits.HasValue)
                            MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    }
                    else
                    {
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
                        }
                    }
                }

                // Track lea reg,[local] for outparam inference.
                if (TryParseLeaRegOfLocal(t, out var leaReg, out var localName))
                {
                    lastLeaLocalByReg[leaReg] = (localName, i);
                }

                // Track push reg window.
                if (TryParsePushReg(t, out var pushedReg))
                {
                    pushWindow.Enqueue(pushedReg);
                    pushRegCounts.TryGetValue(pushedReg, out var pc);
                    pushRegCounts[pushedReg] = pc + 1;

                    while (pushWindow.Count > pushWindowSize)
                    {
                        var old = pushWindow.Dequeue();
                        if (pushRegCounts.TryGetValue(old, out var oc))
                        {
                            oc--;
                            if (oc <= 0)
                                pushRegCounts.Remove(old);
                            else
                                pushRegCounts[old] = oc;
                        }
                    }
                }

                // Invalidate lea-tracked regs if this instruction writes a reg.
                var wm = WritesRegRegex.Match(t);
                if (wm.Success)
                {
                    var dst = wm.Groups["dst"].Value;
                    if (!string.IsNullOrWhiteSpace(dst))
                        lastLeaLocalByReg.Remove(dst);
                }

                // On call, decide whether any recent lea reg,[local] looks like an outparam.
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) && lastLeaLocalByReg.Count > 0)
                {
                    foreach (var kv in lastLeaLocalByReg.ToList())
                    {
                        var reg = kv.Key;
                        var (loc, leaIdx) = kv.Value;
                        if ((i - leaIdx) > 8)
                            continue;

                        var isPushedArg = pushRegCounts.ContainsKey(reg);
                        var isImmediateRegArg = (i - leaIdx) == 1;
                        if (!isPushedArg && !isImmediateRegArg)
                            continue;

                        if (!isPushedArg)
                        {
                            if (hintedLocals.Add(loc))
                                outAliasHints.Add($"VARHINT: {loc} maybe outparam (lea {reg}, [{loc}] immediately before call)");
                            continue;
                        }

                        if (inferredOutAliases.ContainsKey(loc))
                            continue;

                        var alias = MakeOutpAliasFromLocal(loc);
                        if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                            continue;

                        inferredOutAliases[loc] = alias;
                        outAliasHints.Add($"VARALIAS: {loc} -> {alias} (outparam; inferred from push+call)");
                    }
                }
            }

            // Determine calling convention / ret imm.
            for (var i = Math.Min(max, instructions.Count) - 1; i >= startIdx; i--)
            {
                var rt = InsText(instructions[i]).Trim();
                if (!rt.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    continue;

                var mret = Regex.Match(rt, @"^ret\s+(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                if (mret.Success && TryParseHexOrDecUInt32(mret.Groups["imm"].Value, out var imm))
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

        private static void InferOutParamLocalAliasesForFunction(
            string[] cookedByIndex,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (cookedByIndex == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Track most recent address-taken locals per register.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(cookedByIndex.Length, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i] ?? string.Empty;

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

                var pushedRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var back = Math.Max(startIdx, i - 10);
                for (var j = back; j < i; j++)
                {
                    var prev = cookedByIndex[j] ?? string.Empty;
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
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
                foreach (Match m in Regex.Matches(cooked, @"\barg_(?<idx>[0-9]+)\b", RegexOptions.IgnoreCase))
                {
                    if (int.TryParse(m.Groups["idx"].Value, out var idx))
                        usedArgMax = Math.Max(usedArgMax, idx);
                }
            }

            // Find the last ret in the function range.
            for (var i = max - 1; i >= startIdx; i--)
            {
                var t = InsText(instructions[i]).Trim();
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

        private static void InferArgsAndCallingConventionForFunction(
            string[] cookedByIndex,
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

            if (cookedByIndex == null || instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(Math.Min(instructions.Count, endIdx), cookedByIndex.Length);
            var usedArgMax = -1;

            // Fast scan for arg_N tokens without regex.
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i];
                if (string.IsNullOrEmpty(cooked))
                    continue;

                var idx = 0;
                while (idx < cooked.Length)
                {
                    idx = cooked.IndexOf("arg_", idx, StringComparison.OrdinalIgnoreCase);
                    if (idx < 0)
                        break;

                    var j = idx + 4;
                    var n = 0;
                    var any = false;
                    while (j < cooked.Length)
                    {
                        var ch = cooked[j];
                        if (ch < '0' || ch > '9')
                            break;
                        any = true;
                        n = (n * 10) + (ch - '0');
                        if (n > 4096)
                            break;
                        j++;
                    }

                    if (any)
                        usedArgMax = Math.Max(usedArgMax, n);

                    idx = j;
                }
            }

            // Find the last ret in the function range.
            for (var i = max - 1; i >= startIdx; i--)
            {
                var t = InsText(instructions[i]).Trim();
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
                            evidence[local] = ev = new LocalAliasEvidence();
                        ev.Cases.Add(caseVal);
                        ev.Values.Add(v);
                    }

                    if (TryParseRoleNoteAddrTaken(part, out var local2))
                    {
                        if (!evidence.TryGetValue(local2, out var ev2))
                            evidence[local2] = ev2 = new LocalAliasEvidence();
                        ev2.Cases.Add(caseVal);
                        ev2.AddressTaken = true;
                    }
                }
            }

            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in evidence.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var local = kv.Key;
                var ev = kv.Value;

                // Only rename when we have a fairly safe interpretation.
                // - boolean-ish options (only 0/1 writes, and at least one case sets to 1)
                // - address-taken locals (likely out parameters)
                var isBoolish = ev.Values.Count > 0 && ev.Values.All(v => v == 0 || v == 1) && ev.Values.Contains(1);

                byte? chosenCase = ev.Cases.OrderBy(c => c).FirstOrDefault();
                if (ev.Cases.Count > 0)
                    chosenCase = ev.Cases.OrderBy(c => c).First();

                string alias = null;
                if (isBoolish && chosenCase.HasValue)
                    alias = MakeOptAliasFromCase(chosenCase.Value);
                else if (!isBoolish && ev.AddressTaken && chosenCase.HasValue)
                    alias = MakeOutAliasFromCase(chosenCase.Value);

                if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                    continue;

                // Ensure uniqueness.
                var baseAlias = alias;
                var suffix = 2;
                while (used.Contains(alias))
                {
                    alias = baseAlias + "_" + suffix;
                    suffix++;
                }
                used.Add(alias);

                inferredAliases[local] = alias;

                var caseText = string.Join(",", ev.Cases.OrderBy(c => c).Take(8).Select(c => FormatImm8AsChar(c) + $"(0x{c:X2})"));
                var valText = ev.Values.Count > 0 ? $" values={string.Join("/", ev.Values.OrderBy(v => v).Select(v => $"0x{v:X}"))}" : string.Empty;
                var kind = isBoolish ? "bool" : (ev.AddressTaken ? "out" : "local");
                aliasHints.Add($"VARALIAS: {local} -> {alias} ({kind}; cases {caseText}{valText})");
            }
        }
    }
}
