using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
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
    }
}
