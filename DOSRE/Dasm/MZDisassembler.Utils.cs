using System;
using System.Text;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
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
