using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private sealed class FlagBitStats
        {
            public int Total;
            public Dictionary<int, int> BitCounts = new Dictionary<int, int>();
        }

        private static Dictionary<uint, string> BuildInferredFlagSymbols(List<Instruction> instructions, int minTests)
        {
            if (instructions == null || instructions.Count == 0)
                return new Dictionary<uint, string>();

            var counts = new Dictionary<uint, int>();

            foreach (var ins in instructions)
            {
                var t = ins?.ToString();
                if (string.IsNullOrWhiteSpace(t))
                    continue;

                if (!TryParseAbsBitTest(t.Trim(), out var abs, out var mask))
                    continue;
                if (mask == 0 || (mask & (mask - 1)) != 0)
                    continue;

                counts.TryGetValue(abs, out var c);
                counts[abs] = c + 1;
            }

            var map = new Dictionary<uint, string>();
            foreach (var kvp in counts.Where(k => k.Value >= minTests).OrderByDescending(k => k.Value).ThenBy(k => k.Key))
                map[kvp.Key] = $"flags_{kvp.Key:X8}";

            return map;
        }

        private static Dictionary<uint, string> BuildInferredPointerSymbols(List<Instruction> instructions, int minBaseUses)
        {
            if (instructions == null || instructions.Count == 0)
                return new Dictionary<uint, string>();

            var baseUseCounts = new Dictionary<uint, int>();

            for (var i = 0; i < instructions.Count - 1; i++)
            {
                var t = instructions[i]?.ToString();
                if (string.IsNullOrWhiteSpace(t))
                    continue;

                if (!TryParseMovRegFromAbs(t.Trim(), out var reg, out var abs))
                    continue;

                // Ignore obvious scalars (ax/al/etc) and stack regs.
                if (string.IsNullOrEmpty(reg))
                    continue;
                var r = reg.ToLowerInvariant();
                if (r == "esp" || r == "ebp" || r == "sp" || r == "bp")
                    continue;
                if (!(r == "eax" || r == "ebx" || r == "ecx" || r == "edx" || r == "esi" || r == "edi"))
                    continue;

                // Heuristic: within a short window, the loaded reg is used as a memory base (e.g. [esi+0x30]).
                var usedAsBase = false;
                for (var j = i + 1; j < instructions.Count && j <= i + 10; j++)
                {
                    var u = instructions[j]?.ToString();
                    if (string.IsNullOrWhiteSpace(u))
                        continue;

                    // Stop if reg is overwritten quickly.
                    if (Regex.IsMatch(u, $@"^\s*mov\s+{Regex.Escape(r)}\s*,", RegexOptions.IgnoreCase))
                        break;

                    // Count only base uses with smallish displacements; avoids counting random table jumps.
                    var m = Regex.Match(u, $@"\[(?<base>{Regex.Escape(r)})\+(?<disp>0x[0-9A-Fa-f]+|\d+)\]", RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        var dTok = m.Groups["disp"].Value;
                        if (dTok.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        {
                            if (int.TryParse(dTok.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out var d) && d >= 0 && d <= 0x400)
                            {
                                usedAsBase = true;
                                break;
                            }
                        }
                        else
                        {
                            if (int.TryParse(dTok, out var d) && d >= 0 && d <= 0x400)
                            {
                                usedAsBase = true;
                                break;
                            }
                        }
                    }
                }

                if (!usedAsBase)
                    continue;

                baseUseCounts.TryGetValue(abs, out var c);
                baseUseCounts[abs] = c + 1;
            }

            var map = new Dictionary<uint, string>();
            foreach (var kvp in baseUseCounts.Where(k => k.Value >= minBaseUses).OrderByDescending(k => k.Value).ThenBy(k => k.Key))
                map[kvp.Key] = $"ptr_{kvp.Key:X8}";

            return map;
        }

        private static string RewriteFlagSymbols(string insText, Dictionary<uint, string> flagSymbols)
        {
            if (string.IsNullOrWhiteSpace(insText) || flagSymbols == null || flagSymbols.Count == 0)
                return insText;

            // Replace absolute memory operands [0x1234] / [1234h] with [flags_XXXXXXXX] when known.
            return Regex.Replace(
                insText,
                @"\[(?<abs>(?:0x)?[0-9A-Fa-f]+)h?\]",
                m =>
                {
                    var tok = m.Groups["abs"].Value.Trim();
                    tok = tok.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? tok.Substring(2) : tok;
                    if (!uint.TryParse(tok, System.Globalization.NumberStyles.HexNumber, null, out var abs))
                        return m.Value;
                    if (!flagSymbols.TryGetValue(abs, out var name))
                        return m.Value;
                    return $"[{name}]";
                },
                RegexOptions.IgnoreCase);
        }

        private static string RewritePointerSymbols(string insText, Dictionary<uint, string> ptrSymbols)
        {
            if (string.IsNullOrWhiteSpace(insText) || ptrSymbols == null || ptrSymbols.Count == 0)
                return insText;

            return Regex.Replace(
                insText,
                @"\[(?<abs>(?:0x)?[0-9A-Fa-f]+)h?\]",
                m =>
                {
                    var tok = m.Groups["abs"].Value.Trim();
                    tok = tok.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? tok.Substring(2) : tok;
                    if (!uint.TryParse(tok, System.Globalization.NumberStyles.HexNumber, null, out var abs))
                        return m.Value;
                    if (!ptrSymbols.TryGetValue(abs, out var name))
                        return m.Value;
                    return $"[{name}]";
                },
                RegexOptions.IgnoreCase);
        }
    }
}
