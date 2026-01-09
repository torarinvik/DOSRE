using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using DOSRE.Enums;

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

        private static string PseudoCFromLeAsm(string asm)
        {
            if (string.IsNullOrWhiteSpace(asm))
                return string.Empty;

            var lines = asm.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');

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

                sb.AppendLine(proto + "");
                sb.AppendLine("{");

                var pending = new PendingFlags();

                foreach (var block in fn.Blocks)
                {
                    sb.AppendLine($"{SanitizeLabel(block.Label)}:");

                    var suppressTailAfterRetDecode = false;
                    var wroteTailSuppressionNote = false;

                    foreach (var item in block.Lines)
                    {
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
                        {
                            // Once we've hit a post-RET decode region, the remainder is typically not reachable code.
                            continue;
                        }

                        var stmt = TranslateInstructionToPseudoC(item, labelByAddr, pending);
                        if (!string.IsNullOrWhiteSpace(stmt))
                            sb.AppendLine("    " + stmt);
                    }

                    sb.AppendLine();
                }

                sb.AppendLine("}");
                sb.AppendLine();
            }

            return sb.ToString();
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

            public void Clear()
            {
                LastCmpLhs = null;
                LastCmpRhs = null;
                LastWasCmp = false;
                LastTestLhs = null;
                LastTestRhs = null;
                LastWasTest = false;
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
            var m = Regex.Match(
                line,
                @"^(?<addr>[0-9A-Fa-f]{8})h\s+[0-9A-Fa-f]{2,}\s+(?<asm>.+?)\s*(?:;\s*(?<c>.*))?$",
                RegexOptions.None);

            if (!m.Success)
                return null;

            return new ParsedInsOrComment
            {
                Kind = ParsedLineKind.Instruction,
                Raw = line,
                AddrHex = m.Groups["addr"].Value.ToUpperInvariant(),
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

            var commentSuffix = string.IsNullOrWhiteSpace(ins.Comment) ? string.Empty : " // " + ins.Comment;

            // Split mnemonic and operands.
            var m = Regex.Match(asm, @"^(?<mn>[a-zA-Z]+)\s*(?<ops>.*)$");
            if (!m.Success)
                return "/* " + asm + " */" + commentSuffix;

            var mn = m.Groups["mn"].Value.ToLowerInvariant();
            var ops = m.Groups["ops"].Value.Trim();

            string ResolveTarget(string opText)
            {
                var mm = Regex.Match(opText, @"0x(?<addr>[0-9A-Fa-f]{1,8})");
                if (mm.Success)
                {
                    var a = mm.Groups["addr"].Value.PadLeft(8, '0').ToUpperInvariant();
                    if (labelByAddr.TryGetValue(a, out var lab))
                        return SanitizeLabel(lab);
                    return "0x" + a;
                }
                return opText;
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

            if (mn == "mov")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear();
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                return $"{lhs} = {rhs};{commentSuffix}";
            }

            if (mn == "lea")
            {
                var parts = SplitTwoOperands(ops);
                if (parts == null)
                    return "/* " + asm + " */" + commentSuffix;

                pending.Clear();
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

                pending.Clear();

                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);

                if (mn == "xor" && lhs.Equals(rhs, StringComparison.OrdinalIgnoreCase))
                    return $"{lhs} = 0;{commentSuffix}";

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

                pending.Clear();
                var lhs = NormalizeAsmOperandToC(parts.Value.lhs, isMemoryWrite: true);
                var rhs = NormalizeAsmOperandToC(parts.Value.rhs, isMemoryWrite: false);
                var op = mn == "shl" ? "<<=" : ">>=";
                return $"{lhs} {op} {rhs};{commentSuffix}";
            }

            if (mn == "inc" || mn == "dec")
            {
                pending.Clear();
                if (string.IsNullOrWhiteSpace(ops))
                    return "/* " + asm + " */" + commentSuffix;

                var opnd = NormalizeAsmOperandToC(ops, isMemoryWrite: true);
                return mn == "inc" ? $"{opnd}++;{commentSuffix}" : $"{opnd}--;{commentSuffix}";
            }

            if (mn == "call")
            {
                pending.Clear();
                var target = ResolveTarget(ops);
                return $"{target}();{commentSuffix}";
            }

            if (mn == "ret")
            {
                pending.Clear();
                return "return;" + commentSuffix;
            }

            if (mn == "jmp")
            {
                pending.Clear();
                var target = ResolveTarget(ops);
                return $"goto {target};{commentSuffix}";
            }

            if (IsJcc(mn))
            {
                var target = ResolveTarget(ops);
                var cond = TryMakeConditionFromPending(mn, pending);
                pending.Clear();

                if (!string.IsNullOrWhiteSpace(cond))
                    return $"if ({cond}) goto {target};{commentSuffix}";

                return $"if ({mn}) goto {target};{commentSuffix}";
            }

            // Default: keep as comment.
            pending.Clear();
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
                return $"*({ty}*)({expr})";
            }

            // Bare [expr] => assume dword in 32-bit mode.
            var bare = Regex.Match(t, @"^\[(?<expr>.+)\]$", RegexOptions.None);
            if (bare.Success)
            {
                var expr = bare.Groups["expr"].Value.Trim();
                return $"*(uint32_t*)({expr})";
            }

            return t;
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
                if (jcc is "je" or "jz")
                    return $"({a} & {b}) == 0";
                if (jcc is "jne" or "jnz")
                    return $"({a} & {b}) != 0";
            }

            return string.Empty;
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
