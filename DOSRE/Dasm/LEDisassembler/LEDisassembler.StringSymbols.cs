using System;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static readonly Regex StringSymRegex = new Regex("s_[0-9A-Fa-f]{8}", RegexOptions.Compiled);
        private static readonly Regex ResourceSymRegex = new Regex("r_[0-9A-Fa-f]{8}", RegexOptions.Compiled);

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
    }
}
