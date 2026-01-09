using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Enums;

using System.Security.Cryptography;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        public static bool TryDecompileToString(
            string inputFile,
            bool leFull,
            int? leBytesLimit,
            bool leFixups,
            bool leGlobals,
            bool leInsights,
            EnumToolchainHint toolchainHint,
            out string output,
            out string error)
        {
            output = string.Empty;
            error = string.Empty;

            // Decompilation benefits heavily from insights (function labels, CFG labels, alias rewrites).
            // Force it on regardless of the caller's flag.
            var useInsights = true;

            if (!TryDisassembleToString(
                    inputFile,
                    leFull,
                    leBytesLimit,
                    leFixups,
                    leGlobals,
                    useInsights,
                    toolchainHint,
                    out var asm,
                    out error))
            {
                return false;
            }

            output = PseudoCFromLeAsm(asm);
            return true;
        }

        public static bool TryDecompileAsmFileToString(
            string asmFile,
            string onlyFunction,
            out string output,
            out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(asmFile) || !File.Exists(asmFile))
            {
                error = "Invalid asm file";
                return false;
            }

            var asm = File.ReadAllText(asmFile);
            output = PseudoCFromLeAsm(asm, onlyFunction);
            return true;
        }

        public static bool TryDecompileAsmToString(
            string asm,
            string onlyFunction,
            out string output,
            out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(asm))
            {
                error = "Empty asm";
                return false;
            }

            output = PseudoCFromLeAsm(asm, onlyFunction);
            return true;
        }

        private static string PseudoCFromLeAsm(string asm, string onlyFunction = null)
        {
            if (string.IsNullOrWhiteSpace(asm))
                return string.Empty;

            var lines = asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');

            if (!string.IsNullOrWhiteSpace(onlyFunction))
            {
                lines = TrySliceToSingleFunction(lines, onlyFunction);
            }

            var labelByAddr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var functions = new List<ParsedFunction>();

            // Pass 1: collect labels (func_/bb_/loc_)
            foreach (var raw in lines)
            {
                var t = raw.Trim();
                var m = Regex.Match(t, @"^(?<kind>func|bb|loc)_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                if (!m.Success)
                    continue;

                var addr = m.Groups["addr"].Value.ToUpperInvariant();
                var label = $"{m.Groups["kind"].Value}_{addr}";
                labelByAddr[addr] = label;
            }

            // Pass 2: parse functions and instructions
            ParsedFunction currentFunc = null;
            ParsedBlock currentBlock = null;

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                var t = line.TrimEnd();

                var funcHdr = Regex.Match(t.Trim(), @"^func_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                if (funcHdr.Success)
                {
                    currentFunc = new ParsedFunction
                    {
                        Name = $"func_{funcHdr.Groups["addr"].Value.ToUpperInvariant()}",
                        HeaderComments = new List<string>(),
                        Blocks = new List<ParsedBlock>()
                    };
                    functions.Add(currentFunc);
                    currentBlock = null;
                    continue;
                }

                if (currentFunc != null)
                {
                    // Collect header comment lines (PROTO/CC/etc) until first instruction or label.
                    if (t.StartsWith(";", StringComparison.Ordinal) && currentBlock == null)
                    {
                        currentFunc.HeaderComments.Add(t.Trim());
                        continue;
                    }

                    var blockHdr = Regex.Match(t.Trim(), @"^(?<kind>bb|loc)_(?<addr>[0-9A-Fa-f]{8}):\s*$");
                    if (blockHdr.Success)
                    {
                        currentBlock = new ParsedBlock
                        {
                            Label = $"{blockHdr.Groups["kind"].Value}_{blockHdr.Groups["addr"].Value.ToUpperInvariant()}",
                            Lines = new List<ParsedInsOrComment>()
                        };
                        currentFunc.Blocks.Add(currentBlock);
                        continue;
                    }

                    // Instruction line: 0007E060h 56  push esi
                    var ins = TryParseAsmInstructionLine(t);
                    if (ins != null)
                    {
                        if (currentBlock == null)
                        {
                            // Some functions begin with straight instructions before any bb_/loc_ labels.
                            currentBlock = new ParsedBlock { Label = currentFunc.Name, Lines = new List<ParsedInsOrComment>() };
                            currentFunc.Blocks.Add(currentBlock);
                        }

                        currentBlock.Lines.Add(ins);
                        continue;
                    }

                    // Preserve non-empty comment lines inside the function.
                    if (!string.IsNullOrWhiteSpace(t) && currentBlock != null && t.TrimStart().StartsWith(";", StringComparison.Ordinal))
                    {
                        currentBlock.Lines.Add(new ParsedInsOrComment { Kind = ParsedLineKind.Comment, Raw = t.Trim() });
                    }
                }
            }

            // Emit pseudo-C
            var sb = new StringBuilder();
            sb.AppendLine("// DOSRE LE pseudo-decompile (best-effort)");
            sb.AppendLine("// Notes:");
            sb.AppendLine("// - This is not a full decompiler yet; it emits structured pseudo-C with gotos.");
            sb.AppendLine("// - It reuses LE insights/symbolization from the disassembler output.");
            sb.AppendLine("// - Memory operands use uint*_t; assume <stdint.h>.");
            sb.AppendLine("#include <stdint.h>");
            sb.AppendLine();

            foreach (var fn in functions)
            {
                var proto = ExtractProtoFromHeader(fn.HeaderComments);
                if (string.IsNullOrWhiteSpace(proto))
                    proto = $"void {fn.Name}(void)";

                // Checksum calculation: hash of all raw instruction bytes in this function.
                var allBytes = string.Join("", fn.Blocks.SelectMany(b => b.Lines).Where(l => l.Kind == ParsedLineKind.Instruction).Select(l => l.BytesHex));
                var hashStr = string.Empty;
                if (!string.IsNullOrEmpty(allBytes))
                {
                    using (var md5 = MD5.Create())
                    {
                        var hash = md5.ComputeHash(Encoding.ASCII.GetBytes(allBytes));
                        hashStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }

                sb.AppendLine(proto + "");
                sb.AppendLine("{");
                if (!string.IsNullOrEmpty(hashStr))
                {
                    sb.AppendLine($"    // FIDELITY: {hashStr} (checksum of raw bytes)");
                }

                var regs = CollectRegistersUsed(fn);
                if (regs.Any())
                {
                    sb.AppendLine("    uint32_t " + string.Join(", ", regs.OrderBy(r => r)) + ";");
                }

                var pending = new PendingFlags();
                var scopeEnds = new Stack<string>();

                foreach (var block in fn.Blocks)
                {
                    // Close any scopes that end at this block's label.
                    while (scopeEnds.Count > 0 && scopeEnds.Peek() == block.Label)
                    {
                        scopeEnds.Pop();
                        sb.AppendLine("    }");
                    }

                    sb.AppendLine($"{SanitizeLabel(block.Label)}:");

                    var suppressTailAfterRetDecode = false;
                    var wroteTailSuppressionNote = false;

                    for (var lineIdx = 0; lineIdx < block.Lines.Count; lineIdx++)
                    {
                        var item = block.Lines[lineIdx];
                        if (item.Kind == ParsedLineKind.Comment)
                        {
                            sb.AppendLine("    // " + item.Raw.TrimStart(';').Trim());
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(item.Comment) &&
                            item.Comment.Contains("decoded after RET", StringComparison.OrdinalIgnoreCase))
                        {
                            suppressTailAfterRetDecode = true;
                            pending.Clear();
                            if (!wroteTailSuppressionNote)
                            {
                                sb.AppendLine("    // NOTE: omitted tail bytes decoded after RET (likely data/padding)");
                                wroteTailSuppressionNote = true;
                            }
                            continue;
                        }

                        if (suppressTailAfterRetDecode)
                            continue;

                        // Basic If-Structure Detection:
                        // If this is the last instruction in the block, and it's a conditional jump 
                        // jumping over the next few blocks, we can turn it into an 'if'.
                        if (lineIdx == block.Lines.Count - 1 && IsJccLine(item, out var jccMn, out var jccTarget))
                        {
                            var cond = TryMakeConditionFromPending(jccMn, pending);
                            var targetLabel = labelByAddr.GetValueOrDefault(jccTarget);

                            if (!string.IsNullOrWhiteSpace(cond) && !string.IsNullOrWhiteSpace(targetLabel))
                            {
                                // We want to invert the condition to make it "if (!cond) { body }".
                                // This applies if we are jumping over exactly the next set of lines to targetLabel.
                                var inverted = InvertCondition(jccMn, pending);
                                if (!string.IsNullOrWhiteSpace(inverted))
                                {
                                    sb.AppendLine($"    if ({inverted}) {{");
                                    scopeEnds.Push(targetLabel);
                                    pending.Clear();
                                    continue;
                                }

                                sb.AppendLine($"    if ({cond}) goto {SanitizeLabel(targetLabel)};");
                                pending.Clear();
                                continue;
                            }
                        }

                        // Call-site improvement: peek ahead for CALLHINT
                        if (item.Asm.StartsWith("call", StringComparison.OrdinalIgnoreCase))
                        {
                            var hint = string.Empty;
                            for (var j = lineIdx + 1; j < block.Lines.Count && j < lineIdx + 5; j++)
                            {
                                var peek = block.Lines[j];
                                if (peek.Kind == ParsedLineKind.Comment && peek.Raw.Contains("CALLHINT:"))
                                {
                                    hint = peek.Raw;
                                    break;
                                }
                                if (peek.Kind == ParsedLineKind.Instruction) break;
                            }

                            if (!string.IsNullOrWhiteSpace(hint))
                            {
                                var callStmt = TranslateCallWithHint(item, hint, labelByAddr);
                                if (!string.IsNullOrWhiteSpace(callStmt))
                                {
                                    sb.AppendLine("    " + callStmt);
                                    pending.Clear();
                                    continue;
                                }
                            }
                        }

                        // If-Else detection:
                        // If this is the last instruction in the block, and it's an unconditional jump 
                        // jumping over the current 'if' target, it might be an 'else'.
                        if (lineIdx == block.Lines.Count - 1 && item.Asm.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) && scopeEnds.Count > 0)
                        {
                            var targetAddr = item.Asm.Substring(4).Trim().TrimStart('0', 'x').ToUpperInvariant().PadLeft(8, '0');
                            var targetLabel = labelByAddr.GetValueOrDefault(targetAddr);
                            if (targetLabel != null && targetLabel != scopeEnds.Peek())
                            {
                                sb.AppendLine("    } else {");
                                scopeEnds.Pop();
                                scopeEnds.Push(targetLabel);
                                pending.Clear(false); // Flags don't cross else usually, but we keep EAX
                                continue;
                            }
                        }

                        // Basic loop detection (do-while style)
                        if (lineIdx == block.Lines.Count - 1 && IsJccLine(item, out var loopMn, out var loopTarget))
                        {
                             var loopTargetLabel = labelByAddr.GetValueOrDefault(loopTarget);
                             // If it jumps BACK to a label we've already seen in this function, it's a loop.
                             // For now, we don't 'structure' it as a while() but we can comment it.
                        }

                        var stmt = TranslateInstructionToPseudoC(item, labelByAddr, pending);
                        if (!string.IsNullOrWhiteSpace(stmt))
                        {
                            // Heuristic: convert "return;" after "eax = ...;" into "return eax;"
                            if (stmt == "return;" && !string.IsNullOrWhiteSpace(pending.LastEaxAssignment))
                            {
                                sb.AppendLine($"    return {pending.LastEaxAssignment};");
                                pending.LastEaxAssignment = null;
                            }
                            else
                            {
                                sb.AppendLine("    " + stmt);
                            }
                        }
                    }
                }

                while (scopeEnds.Count > 0)
                {
                    scopeEnds.Pop();
                    sb.AppendLine("    }");
                }

                sb.AppendLine("}");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static string[] TrySliceToSingleFunction(string[] lines, string onlyFunction)
        {
            if (lines == null || lines.Length == 0)
                return lines;

            var needle = onlyFunction.Trim();
            if (needle.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                needle = needle.Substring(2);
            needle = needle.Trim();

            if (Regex.IsMatch(needle, @"^[0-9A-Fa-f]{1,8}$"))
            {
                needle = needle.PadLeft(8, '0').ToUpperInvariant();
                needle = "func_" + needle;
            }

            if (!needle.StartsWith("func_", StringComparison.OrdinalIgnoreCase))
                needle = "func_" + needle;

            var start = -1;
            for (var i = 0; i < lines.Length; i++)
            {
                var t = lines[i].Trim();
                if (t.StartsWith(needle + ":", StringComparison.OrdinalIgnoreCase))
                {
                    start = i;
                    break;
                }
            }

            if (start < 0)
                return lines;

            var end = lines.Length;
            for (var i = start + 1; i < lines.Length; i++)
            {
                var t = lines[i].Trim();
                if (Regex.IsMatch(t, @"^func_[0-9A-Fa-f]{8}:\s*$"))
                {
                    end = i;
                    break;
                }
            }

            // Also keep a little prelude so label collection has a chance to see targets.
            var preludeStart = Math.Max(0, start - 50);
            return lines.Skip(preludeStart).Take(end - preludeStart).ToArray();
        }

        private static HashSet<string> CollectRegistersUsed(ParsedFunction fn)
        {
            var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var regMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["al"] = "eax", ["ah"] = "eax", ["ax"] = "eax", ["eax"] = "eax",
                ["bl"] = "ebx", ["bh"] = "ebx", ["bx"] = "ebx", ["ebx"] = "ebx",
                ["cl"] = "ecx", ["ch"] = "ecx", ["cx"] = "ecx", ["ecx"] = "ecx",
                ["dl"] = "edx", ["dh"] = "edx", ["dx"] = "edx", ["edx"] = "edx",
                ["si"] = "esi", ["esi"] = "esi",
                ["di"] = "edi", ["edi"] = "edi",
                ["bp"] = "ebp", ["ebp"] = "ebp"
            };

            foreach (var block in fn.Blocks)
            {
                foreach (var line in block.Lines)
                {
                    if (line.Kind != ParsedLineKind.Instruction) continue;
                    foreach (var kvp in regMap)
                    {
                        if (Regex.IsMatch(line.Asm, $@"\b{kvp.Key}\b", RegexOptions.IgnoreCase))
                        {
                            res.Add(kvp.Value);
                        }
                    }
                }
            }
            return res;
        }

        private static string TranslateCallWithHint(ParsedInsOrComment callIns, string hint, Dictionary<string, string> labelByAddr)
        {
            var targetRaw = callIns.Asm.Substring(4).Trim();

            string ResolveCallTarget(string opText)
            {
                // If it's already a symbol like func_XXXXXXXX, keep it but sanitize.
                if (opText.StartsWith("func_", StringComparison.OrdinalIgnoreCase) || 
                    opText.StartsWith("loc_", StringComparison.OrdinalIgnoreCase) || 
                    opText.StartsWith("bb_", StringComparison.OrdinalIgnoreCase))
                {
                    return SanitizeLabel(opText);
                }

                var mm = Regex.Match(opText.Trim(), @"(?:0x)?(?<addr>[0-9A-Fa-f]{1,8})");
                if (mm.Success)
                {
                    var a = mm.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                    if (labelByAddr.TryGetValue(a, out var lab))
                        return SanitizeLabel(lab);
                    return "func_" + a;
                }
                return SanitizeLabel(opText);
            }

            var target = ResolveCallTarget(targetRaw);

            var argsMatch = Regex.Match(hint, @"args~(?<count>\d+)");
            var retMatch = Regex.Match(hint, @"ret=(?<ret>[^\s,)]+)");
            var regHints = Regex.Matches(hint, @"reg~(?<reg>[a-z]{2,3})=(?<val>\[[^\]]+\]|[^\s,]+)");

            var argList = new List<string>();
            foreach (Match rm in regHints)
            {
                var v = rm.Groups["val"].Value.Trim();
                if (v.EndsWith(",")) v = v.Substring(0, v.Length - 1);
                argList.Add(NormalizeAsmOperandToC(v, false));
            }

            var retVar = string.Empty;
            if (retMatch.Success && !retMatch.Groups["ret"].Value.Contains("unused"))
            {
                retVar = retMatch.Groups["ret"].Value + " = ";
            }

            return $"{retVar}{target}({string.Join(", ", argList)});";
        }

        private static string ResolveTarget(string opText, Dictionary<string, string> labelByAddr)
        {
            if (opText.StartsWith("func_", StringComparison.OrdinalIgnoreCase) || 
                opText.StartsWith("loc_", StringComparison.OrdinalIgnoreCase) || 
                opText.StartsWith("bb_", StringComparison.OrdinalIgnoreCase))
            {
                return SanitizeLabel(opText);
            }

            var mm = Regex.Match(opText.Trim(), @"(?:0x)?(?<addr>[0-9A-Fa-f]{1,8})");
            if (mm.Success)
            {
                var a = mm.Groups["addr"].Value.ToUpperInvariant().PadLeft(8, '0');
                if (labelByAddr.TryGetValue(a, out var lab))
                    return SanitizeLabel(lab);
                return "loc_" + a;
            }
            return SanitizeLabel(opText);
        }

        private static string InvertCondition(string jcc, PendingFlags pending)
        {
            var invJcc = jcc switch
            {
                "je" or "jz" => "jne",
                "jne" or "jnz" => "je",
                "jl" => "jge",
                "jle" => "jg",
                "jg" => "jle",
                "jge" => "jl",
                "jb" => "jae",
                "jbe" => "ja",
                "ja" => "jbe",
                "jae" => "jb",
                _ => null
            };

            if (invJcc == null) return null;
            return TryMakeConditionFromPending(invJcc, pending);
        }

        private static bool IsJccLine(ParsedInsOrComment ins, out string mn, out string targetAddr)
        {
            mn = null;
            targetAddr = null;
            if (ins == null || ins.Kind != ParsedLineKind.Instruction) return false;

            var m = Regex.Match(ins.Asm, @"^(?<mn>j[a-z]+)\s+0x(?<addr>[0-9A-Fa-f]{1,8})$");
            if (!m.Success) return false;

            mn = m.Groups["mn"].Value.ToLowerInvariant();
            targetAddr = m.Groups["addr"].Value.PadLeft(8, '0').ToUpperInvariant();
            return IsJcc(mn);
        }

        private enum ParsedLineKind
        {
            Instruction,
            Comment
        }

        private sealed class ParsedInsOrComment
        {
            public ParsedLineKind Kind;
            public string Raw;

            public string AddrHex;
            public string BytesHex;
            public string Asm;
            public string Comment;
        }

        private sealed class ParsedBlock
        {
            public string Label;
            public List<ParsedInsOrComment> Lines;
        }

        private sealed class ParsedFunction
        {
            public string Name;
            public List<string> HeaderComments;
            public List<ParsedBlock> Blocks;
        }

        private sealed class PendingFlags
        {
            public string LastCmpLhs;
            public string LastCmpRhs;
            public bool LastWasCmp;

            public string LastTestLhs;
            public string LastTestRhs;
            public bool LastWasTest;

            public string LastEaxAssignment;

            public void Clear(bool targetIsEax = false)
            {
                LastCmpLhs = null;
                LastCmpRhs = null;
                LastWasCmp = false;
                LastTestLhs = null;
                LastTestRhs = null;
                LastWasTest = false;
                if (targetIsEax) LastEaxAssignment = null;
            }

            public void ClearAll()
            {
                Clear(true);
            }
        }

        private static string ExtractProtoFromHeader(List<string> headerLines)
        {
            if (headerLines == null)
                return string.Empty;

            foreach (var l in headerLines)
            {
                var t = l.Trim();
                var m = Regex.Match(t, @"^;\s*PROTO:\s*(?<p>.+?)\s*$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var proto = m.Groups["p"].Value.Trim();
                    // If it's already a C-like prototype, keep it; else wrap.
                    if (proto.Contains('('))
                    {
                        // Some headers currently emit name-only prototypes like "func_XXXXXXXX()".
                        // Normalize to valid C by defaulting the return type to void.
                        var beforeParen = proto.Split('(')[0].Trim();
                        if (!beforeParen.Contains(' '))
                            return "void " + proto;

                        return proto;
                    }
                }
            }

            return string.Empty;
        }

        private static string SanitizeLabel(string label)
        {
            if (string.IsNullOrWhiteSpace(label))
                return "L";

            // Keep it a valid C label: [A-Za-z_][A-Za-z0-9_]*
            var s = Regex.Replace(label, "[^A-Za-z0-9_]", "_");
            if (!char.IsLetter(s[0]) && s[0] != '_')
                s = "L_" + s;
            return s;
        }

        private static ParsedInsOrComment TryParseAsmInstructionLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;

            // Example:
            // 0007E06Bh C6061B          mov byte [ptr_...], 0x1b              ; HINT: ...
            // Pattern: addr 'h' space bytes space asm (trimmed) ';' comment
            var m = Regex.Match(
                line,
                @"^(?<addr>[0-9A-Fa-f]{8})h\s+(?<bytes>[0-9A-Fa-f]+)\s+(?<asm>.+?)\s*(?:;\s*(?<c>.*))?$",
                RegexOptions.None);

            if (!m.Success)
                return null;

            return new ParsedInsOrComment
            {
                Kind = ParsedLineKind.Instruction,
                Raw = line,
                AddrHex = m.Groups["addr"].Value.ToUpperInvariant(),
                BytesHex = m.Groups["bytes"].Value.ToUpperInvariant(),
                Asm = m.Groups["asm"].Value.Trim(),
                Comment = m.Groups["c"].Value.Trim()
            };
        }

        private static string TranslateInstructionToPseudoC(
            ParsedInsOrComment ins,
            Dictionary<string, string> labelByAddr,
            PendingFlags pending)
        {
            var asm = ins.Asm;
            if (string.IsNullOrWhiteSpace(asm))
                return string.Empty;

            var commentSuffix = (string.IsNullOrWhiteSpace(ins.Comment) ? string.Empty : " // " + ins.Comment) + (string.IsNullOrWhiteSpace(ins.BytesHex) ? string.Empty : $" /* RAW: {ins.BytesHex} */");

            // Split mnemonic and operands.
            var m = Regex.Match(asm, @"^(?<mn>[a-zA-Z]+)\s*(?<ops>.*)$");
            if (!m.Success)
                return "/* " + asm + " */" + commentSuffix;

            var mn = m.Groups["mn"].Value.ToLowerInvariant();
            var ops = m.Groups["ops"].Value.Trim();

            // Heuristic for EAX modification
            bool dstIsEax = false;
            if (mn is "mov" or "lea" or "add" or "sub" or "and" or "or" or "xor" or "shl" or "shr" or "sar")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null && parts.Value.lhs.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn == "shrd")
            {
                var parts = SplitThreeOperands(ops);
                if (parts != null && parts.Value.o1.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn is "inc" or "dec" or "pop")
            {
                if (ops.Trim().Equals("eax", StringComparison.OrdinalIgnoreCase))
                    dstIsEax = true;
            }
            else if (mn is "imul" or "idiv")
            {
                dstIsEax = true;
            }

            // Track flag-setting ops for the next conditional jump.
            if (mn == "cmp")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    pending.LastWasCmp = true;
                    pending.LastWasTest = false;
                    pending.LastCmpLhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false);
                    pending.LastCmpRhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                }
                return "// " + asm + commentSuffix;
            }
            if (mn == "test")
            {
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    pending.LastWasTest = true;
                    pending.LastWasCmp = false;
                    pending.LastTestLhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false);
                    pending.LastTestRhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                }
                return "// " + asm + commentSuffix;
            }

            if (mn == "rep")
            {
                pending.Clear(dstIsEax);
                var subMn = ops.ToLowerInvariant();
                if (subMn == "movsd") return $"memcpy(edi, esi, ecx * 4);{commentSuffix}";
                if (subMn == "movsw") return $"memcpy(edi, esi, ecx * 2);{commentSuffix}";
                if (subMn == "movsb") return $"memcpy(edi, esi, ecx);{commentSuffix}";
                if (subMn == "stosd") return $"memset_32(edi, eax, ecx);{commentSuffix}";
                if (subMn == "stosw") return $"memset_16(edi, ax, ecx);{commentSuffix}";
                if (subMn == "stosb") return $"memset(edi, al, ecx);{commentSuffix}";
            }

            if (mn == "imul")
            {
                pending.Clear(dstIsEax);
                var parts = SplitTwoOperands(ops);
                if (parts != null)
                {
                    var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                    var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                    return $"{lhs} *= {rhs};{commentSuffix}";
                }
                else if (!string.IsNullOrWhiteSpace(ops))
                {
                    // Single operand imul: edx:eax = eax * ops
                    var src = NormalizeAsmOperandToC(ops, isMemoryWrite: false);
                    return $"{{ int64_t res = (int64_t)eax * (int64_t){src}; eax = (uint32_t)res; edx = (uint32_t)(res >> 32); }}{commentSuffix}";
                }
            }

            if (mn == "idiv")
            {
                pending.Clear(dstIsEax);
                if (!string.IsNullOrWhiteSpace(ops))
                {
                    var divisor = NormalizeAsmOperandToC(ops, isMemoryWrite: false);
                    return $"{{ int64_t dividend = ((int64_t)edx << 32) | eax; eax = (uint32_t)(dividend / (int32_t){divisor}); edx = (uint32_t)(dividend % (int32_t){divisor}); }}{commentSuffix}";
                }
            }

            if (mn == "shrd")
            {
                pending.Clear(dstIsEax);
                // shrd dest, src, count => dest = (dest >> count) | (src << (32 - count))
                var parts = SplitThreeOperands(ops);
                if (parts != null)
                {
                    var dst = NormalizeAsmOperandToC(parts.Value.o1, isMemoryWrite: true);
                    var src = NormalizeAsmOperandToC(parts.Value.o2, isMemoryWrite: false);
                    var amt = NormalizeAsmOperandToC(parts.Value.o3, isMemoryWrite: false);
                    return $"{dst} = ({dst} >> {amt}) | ({src} << (32 - {amt}));{commentSuffix}";
                }
            }

            if (mn == "push")
            {
                pending.Clear(dstIsEax);
                return $"// push {NormalizeAsmOperandToC(ops, false)};";
            }
            if (mn == "pop")
            {
                pending.Clear(dstIsEax);
                return $"// {NormalizeAsmOperandToC(ops, true)} = pop();";
            }

            if (mn == "mov")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                if (lhs == "eax") pending.LastEaxAssignment = rhs;
                return $"{lhs} = {rhs};{commentSuffix}";
            }

            if (mn == "lea")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                // Heuristic: lea dst, [expr] => dst = (expr);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: false);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                // If the RHS is a dereference (e.g. *(uint32_t*)(...)), de-pointer it for LEA.
                rhs = StripSingleDeref(rhs);
                return $"{lhs} = {rhs};{commentSuffix}";
            }

            if (mn is "add" or "sub" or "and" or "or" or "xor")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);

                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);

                if (mn == "xor" && lhs.Equals(rhs, StringComparison.OrdinalIgnoreCase))
                {
                    if (lhs == "eax") pending.LastEaxAssignment = "0";
                    return $"{lhs} = 0;{commentSuffix}";
                }

                var op = mn switch
                {
                    "add" => "+=",
                    "sub" => "-=",
                    "and" => "&=",
                    "or" => "|=",
                    "xor" => "^=",
                    _ => "="
                };
                return $"{lhs} {op} {rhs};{commentSuffix}";
            }

            if (mn is "shl" or "shr" or "sar")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear(dstIsEax);
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                var op = mn == "shl" ? "<<=" : ">>=";
                return $"{lhs} {op} {rhs};{commentSuffix}";
            }

            if (mn == "inc" || mn == "dec")
            {
                pending.Clear(dstIsEax);
                if (string.IsNullOrWhiteSpace(ops))
                    return "/* " + asm + " */" + commentSuffix;

                var opnd = NormalizeAsmOperandToC(ops, isMemoryWrite: true);
                return mn == "inc" ? $"{opnd}++;{commentSuffix}" : $"{opnd}--;{commentSuffix}";
            }

            if (mn == "call")
            {
                pending.Clear(dstIsEax);
                var target = ResolveTarget(ops, labelByAddr);
                return $"{target}();{commentSuffix}";
            }

            if (mn == "ret")
            {
                var retVal = pending.LastEaxAssignment != null ? " " + pending.LastEaxAssignment : "";
                pending.Clear(true);
                return $"return{retVal};{commentSuffix}";
            }

            if (mn == "jmp")
            {
                pending.Clear(dstIsEax);
                var target = ResolveTarget(ops, labelByAddr);
                return $"goto {target};{commentSuffix}";
            }

            if (IsJcc(mn))
            {
                var target = ResolveTarget(ops, labelByAddr);
                var cond = TryMakeConditionFromPending(mn, pending);
                pending.Clear(dstIsEax);

                if (!string.IsNullOrWhiteSpace(cond))
                    return $"if ({cond}) goto {target};{commentSuffix}";

                return $"if ({mn}) goto {target};{commentSuffix}";
            }

            // Default: keep as comment.
            pending.Clear(dstIsEax);
            return "// " + asm + commentSuffix;
        }

        private static string NormalizeAsmOperandToC(string op, bool isMemoryWrite)
        {
            if (string.IsNullOrWhiteSpace(op))
                return string.Empty;

            var t = op.Trim();

            // Already looks like a C-ish deref; leave it.
            if (t.StartsWith("*", StringComparison.Ordinal))
                return t;

            // byte/word/dword/qword [expr]  (optionally with 'ptr')
            var sized = Regex.Match(
                t,
                @"^(?<sz>byte|word|dword|qword)\s+(?:ptr\s+)?\[(?<expr>.+)\]$",
                RegexOptions.IgnoreCase);

            if (sized.Success)
            {
                var sz = sized.Groups["sz"].Value.ToLowerInvariant();
                var expr = sized.Groups["expr"].Value.Trim();
                var ty = sz switch
                {
                    "byte" => "uint8_t",
                    "word" => "uint16_t",
                    "dword" => "uint32_t",
                    "qword" => "uint64_t",
                    _ => "uint32_t"
                };
                return $"*({ty}*)({WrapExprForPointerMath(expr)})";
            }

            // Bare [expr] => assume dword in 32-bit mode.
            var bare = Regex.Match(t, @"^\[(?<expr>.+?)\]$", RegexOptions.None);
            if (bare.Success)
            {
                var expr = bare.Groups["expr"].Value.Trim();
                return $"*(uint32_t*)({WrapExprForPointerMath(expr)})";
            }

            return t;
        }

        private static string WrapExprForPointerMath(string expr)
        {
            if (string.IsNullOrWhiteSpace(expr))
                return expr;

            // Heuristic: if it's a register + offset, cast the register to uint8_t* 
            // to ensure byte-based pointer arithmetic in the pseudo-C.
            var regMatch = Regex.Match(expr, @"^(?<reg>eax|ebx|ecx|edx|esi|edi|ebp|esp)(?<rest>[\+\-].+)$", RegexOptions.IgnoreCase);
            if (regMatch.Success)
            {
                return $"(uint8_t*){regMatch.Groups["reg"].Value} {regMatch.Groups["rest"].Value}";
            }

            return expr;
        }

        private static string StripSingleDeref(string expr)
        {
            if (string.IsNullOrWhiteSpace(expr))
                return expr;

            // *(uint32_t*)(something)  =>  (something)
            var m = Regex.Match(expr.Trim(), @"^\*\([^\)]*\)\((?<inner>.*)\)$");
            if (m.Success)
                return m.Groups["inner"].Value.Trim();

            return expr;
        }

        private static bool IsJcc(string mn)
        {
            return mn is "jz" or "jnz" or "je" or "jne" or "jg" or "jge" or "jl" or "jle" or "ja" or "jae" or "jb" or "jbe" or "jo" or "jno" or "js" or "jns";
        }

        private static string TryMakeConditionFromPending(string jcc, PendingFlags pending)
        {
            if (pending == null)
                return string.Empty;

            if (pending.LastWasCmp && !string.IsNullOrWhiteSpace(pending.LastCmpLhs))
            {
                var a = pending.LastCmpLhs;
                var b = pending.LastCmpRhs;
                return jcc switch
                {
                    "je" or "jz" => $"{a} == {b}",
                    "jne" or "jnz" => $"{a} != {b}",
                    "jl" => $"{a} < {b}",
                    "jle" => $"{a} <= {b}",
                    "jg" => $"{a} > {b}",
                    "jge" => $"{a} >= {b}",
                    "js" => $"((int32_t)({a}) - (int32_t)({b})) < 0",
                    "jns" => $"((int32_t)({a}) - (int32_t)({b})) >= 0",
                    // Unsigned comparisons (best-effort; keep explicit cast to show intent).
                    "jb" => $"(uint){a} < (uint){b}",
                    "jbe" => $"(uint){a} <= (uint){b}",
                    "ja" => $"(uint){a} > (uint){b}",
                    "jae" => $"(uint){a} >= (uint){b}",
                    _ => string.Empty
                };
            }

            if (pending.LastWasTest && !string.IsNullOrWhiteSpace(pending.LastTestLhs))
            {
                var a = pending.LastTestLhs;
                var b = pending.LastTestRhs;

                // Simple case: test reg, reg => check if reg is 0, negative, etc.
                if (a.Equals(b, StringComparison.OrdinalIgnoreCase))
                {
                    return jcc switch
                    {
                        "je" or "jz" => $"{a} == 0",
                        "jne" or "jnz" => $"{a} != 0",
                        "js" => $"(int32_t){a} < 0",
                        "jns" => $"(int32_t){a} >= 0",
                        "jg" => $"(int32_t){a} > 0",
                        "jge" => $"(int32_t){a} >= 0",
                        "jl" => $"(int32_t){a} < 0",
                        "jle" => $"(int32_t){a} <= 0",
                        _ => string.Empty
                    };
                }

                if (jcc is "je" or "jz")
                    return $"({a} & {b}) == 0";
                if (jcc is "jne" or "jnz")
                    return $"({a} & {b}) != 0";
            }

            return string.Empty;
        }

        private static (string o1, string o2, string o3)? SplitThreeOperands(string ops)
        {
            if (string.IsNullOrWhiteSpace(ops))
                return null;

            var items = new List<string>();
            var depth = 0;
            var start = 0;
            for (var i = 0; i < ops.Length; i++)
            {
                var c = ops[i];
                if (c == '[') depth++;
                else if (c == ']') depth = Math.Max(0, depth - 1);
                else if (c == ',' && depth == 0)
                {
                    items.Add(ops.Substring(start, i - start).Trim());
                    start = i + 1;
                }
            }
            items.Add(ops.Substring(start).Trim());

            if (items.Count == 3)
                return (items[0], items[1], items[2]);

            return null;
        }

        private static (string lhs, string rhs)? SplitTwoOperands(string ops)
        {
            if (string.IsNullOrWhiteSpace(ops))
                return null;

            // Split on the first comma not inside brackets.
            var depth = 0;
            for (var i = 0; i < ops.Length; i++)
            {
                var c = ops[i];
                if (c == '[')
                    depth++;
                else if (c == ']')
                    depth = Math.Max(0, depth - 1);
                else if (c == ',' && depth == 0)
                {
                    var lhs = ops.Substring(0, i).Trim();
                    var rhs = ops.Substring(i + 1).Trim();
                    if (string.IsNullOrWhiteSpace(lhs) || string.IsNullOrWhiteSpace(rhs))
                        return null;
                    return (lhs, rhs);
                }
            }

            return null;
        }
    }
}
