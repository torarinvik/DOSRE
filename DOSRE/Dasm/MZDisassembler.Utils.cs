using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
        private static void SplitInstructionAndComments(string insText, out string instruction, out List<string> comments)
        {
            instruction = insText ?? string.Empty;
            comments = new List<string>();
            if (string.IsNullOrEmpty(insText))
                return;

            // We only treat " ; " as a comment separator so we don't break things like "[ss:0x10]".
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

        private static ushort ReadUInt16(byte[] b, int off)
        {
            if (b == null || off + 2 > b.Length) return 0;
            return (ushort)(b[off] | (b[off + 1] << 8));
        }

        private static uint ReadUInt32(byte[] b, int off)
        {
            if (b == null || off + 4 > b.Length) return 0;
            return (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
        }

        private static string EscapeForComment(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            var sb = new StringBuilder();
            foreach (var c in s)
            {
                if (c == '\r') sb.Append("\\r");
                else if (c == '\n') sb.Append("\\n");
                else if (c == '\t') sb.Append("\\t");
                else if (c < 0x20 || c > 0x7E) sb.Append($"\\x{(int)c:X2}");
                else sb.Append(c);
            }
            return sb.ToString().Replace("\"", "\\\"");
        }
    }
}
