using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        [ThreadStatic]
        private static string s_externalIdaMapPath;

        [ThreadStatic]
        private static string s_externalBinaryNinjaIrPath;

        private sealed class ExternalSymbol
        {
            public string Source;
            public uint Offset;
            public string Name;
        }

        private static readonly Regex IdaMapLineRegex = new Regex(
            @"^\s*(?<seg>[0-9A-Fa-f]{4}):(?<off>[0-9A-Fa-f]{8})\s+(?<name>\S+)\s*$",
            RegexOptions.Compiled);

        private static readonly Regex BinaryNinjaSymLineRegex = new Regex(
            // Examples:
            // 00000067    void* __convention("fastcall") sub_67(...)
            // 0000011c    int32_t __convention("regparm") sub_11c(...)
            // 00000004  data_4:
            @"^(?<off>[0-9A-Fa-f]{8})\s+(?:(?:[A-Za-z_][^\n]*\s+)?)(?<name>(?:sub|loc|data|jpt|byte|word|dword|off|unk)_[0-9A-Fa-f]+)\b",
            RegexOptions.Compiled);

        private static List<ExternalSymbol> LoadExternalSymbolsFromIdaMap(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return new List<ExternalSymbol>();

            var list = new List<ExternalSymbol>();
            foreach (var line in File.ReadLines(path))
            {
                var m = IdaMapLineRegex.Match(line);
                if (!m.Success)
                    continue;

                // We only use the offset; segment is usually constant in these flat exports.
                var offHex = m.Groups["off"].Value;
                if (!uint.TryParse(offHex, System.Globalization.NumberStyles.HexNumber, null, out var off))
                    continue;

                var name = m.Groups["name"].Value;
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                list.Add(new ExternalSymbol { Source = "IDA", Offset = off, Name = name });
            }

            return list;
        }

        private static List<ExternalSymbol> LoadExternalSymbolsFromBinaryNinjaIr(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return new List<ExternalSymbol>();

            var list = new List<ExternalSymbol>();
            foreach (var line in File.ReadLines(path))
            {
                var m = BinaryNinjaSymLineRegex.Match(line);
                if (!m.Success)
                    continue;

                var offHex = m.Groups["off"].Value;
                if (!uint.TryParse(offHex, System.Globalization.NumberStyles.HexNumber, null, out var off))
                    continue;

                var name = m.Groups["name"].Value;
                if (string.IsNullOrWhiteSpace(name))
                    continue;

                list.Add(new ExternalSymbol { Source = "BN", Offset = off, Name = name });
            }

            return list;
        }

        private static string NormalizeAlphaNumLower(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;

            var sb = new StringBuilder(s.Length);
            foreach (var ch in s)
            {
                if (char.IsLetterOrDigit(ch))
                    sb.Append(char.ToLowerInvariant(ch));
            }
            return sb.ToString();
        }

        private static bool TryInferDeltaFromStringLabels(
            List<ExternalSymbol> idaSymbols,
            Dictionary<uint, string> stringPreview,
            out uint delta,
            out int support)
        {
            delta = 0;
            support = 0;
            if (idaSymbols == null || idaSymbols.Count == 0 || stringPreview == null || stringPreview.Count == 0)
                return false;

            // Prepare searchable string list.
            var strings = stringPreview
                .Select(kvp => (addr: kvp.Key, norm: NormalizeAlphaNumLower(kvp.Value)))
                .Where(x => !string.IsNullOrWhiteSpace(x.norm) && x.norm.Length >= 4)
                .ToList();

            // Candidate deltas from best-effort matches: aFooBar -> "...foobar...".
            var deltaCounts = new Dictionary<uint, int>();

            foreach (var sym in idaSymbols)
            {
                if (sym == null || string.IsNullOrWhiteSpace(sym.Name))
                    continue;
                if (!sym.Name.StartsWith("a", StringComparison.Ordinal))
                    continue;

                var frag = sym.Name.Substring(1);
                var normFrag = NormalizeAlphaNumLower(frag);
                if (normFrag.Length < 4)
                    continue;

                // Find best match: longest fragment match inside any string.
                uint bestAddr = 0;
                var bestScore = 0;
                foreach (var s in strings)
                {
                    if (s.norm.Contains(normFrag, StringComparison.Ordinal))
                    {
                        var score = normFrag.Length;
                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestAddr = s.addr;
                        }
                    }
                }

                if (bestScore <= 0 || bestAddr == 0)
                    continue;

                // Only accept deltas where bestAddr >= offset.
                if (bestAddr < sym.Offset)
                    continue;

                var d = bestAddr - sym.Offset;
                if (!deltaCounts.TryGetValue(d, out var c))
                    deltaCounts[d] = 1;
                else
                    deltaCounts[d] = c + 1;
            }

            if (deltaCounts.Count == 0)
                return false;

            var best = deltaCounts.OrderByDescending(k => k.Value).ThenBy(k => k.Key).First();
            delta = best.Key;
            support = best.Value;
            return support >= 2; // require at least a tiny amount of agreement
        }

        private static bool IsAutoGeneratedDataName(string source, string name)
        {
            if (source == "BN")
            {
                return name.StartsWith("data_", StringComparison.Ordinal);
            }
            if (source == "IDA")
            {
                return name.StartsWith("byte_", StringComparison.Ordinal) ||
                       name.StartsWith("word_", StringComparison.Ordinal) ||
                       name.StartsWith("dword_", StringComparison.Ordinal) ||
                       name.StartsWith("qword_", StringComparison.Ordinal) ||
                       name.StartsWith("unk_", StringComparison.Ordinal);
            }
            return false;
        }

        private static void FilterNoisyExternalHints(
            Dictionary<uint, List<string>> hints,
            HashSet<uint> interestingAddresses)
        {
            if (hints == null) return;

            var toRemove = new List<(uint, string)>();
            foreach (var kvp in hints)
            {
                var addr = kvp.Key;
                if (interestingAddresses != null && interestingAddresses.Contains(addr))
                    continue;

                foreach (var tag in kvp.Value)
                {
                    var colonIdx = tag.IndexOf(':');
                    if (colonIdx < 0) continue;
                    var source = tag.Substring(0, colonIdx);
                    var name = tag.Substring(colonIdx + 1);

                    if (IsAutoGeneratedDataName(source, name))
                    {
                        toRemove.Add((addr, tag));
                    }
                }
            }

            foreach (var (addr, tag) in toRemove)
            {
                if (hints.TryGetValue(addr, out var list))
                {
                    list.Remove(tag);
                    if (list.Count == 0)
                        hints.Remove(addr);
                }
            }
        }

        private static Dictionary<uint, List<string>> BuildExternalNameHintsByLinear(
            List<LEObject> objects,
            Dictionary<uint, string> stringPreview,
            string idaMapPath,
            string binaryNinjaIrPath)
        {
            var all = new List<ExternalSymbol>();
            all.AddRange(LoadExternalSymbolsFromIdaMap(idaMapPath));
            all.AddRange(LoadExternalSymbolsFromBinaryNinjaIr(binaryNinjaIrPath));

            if (all.Count == 0 || objects == null || objects.Count == 0)
                return null;

            // Candidate deltas:
            //  - LE object base addresses (map “offset within object” to “linear”).
            //  - plus an inferred delta from IDA string labels to DOSRE string table (maps “IDA flat offset” to “linear”).
            var candidateDeltas = new List<uint>();
            foreach (var o in objects)
            {
                if (o.Index == 0)
                    continue;
                if (o.VirtualSize == 0)
                    continue;
                candidateDeltas.Add(unchecked((uint)o.BaseAddress));
            }

            var idaSyms = all.Where(s => s.Source == "IDA").ToList();
            if (TryInferDeltaFromStringLabels(idaSyms, stringPreview, out var stringDelta, out var support))
            {
                candidateDeltas.Add(stringDelta);
            }

            // Dedupe and keep stable order: object bases first, then inferred.
            candidateDeltas = candidateDeltas.Distinct().ToList();

            var result = new Dictionary<uint, List<string>>();

            foreach (var sym in all)
            {
                if (sym == null || string.IsNullOrWhiteSpace(sym.Name))
                    continue;

                uint chosenLinear = 0;
                foreach (var d in candidateDeltas)
                {
                    var lin = unchecked(sym.Offset + d);
                    if (TryMapLinearToObject(objects, lin, out _, out _))
                    {
                        chosenLinear = lin;
                        break;
                    }
                }

                if (chosenLinear == 0)
                    continue;

                var tag = sym.Source == "IDA" ? $"IDA:{sym.Name}" : $"BN:{sym.Name}";
                if (!result.TryGetValue(chosenLinear, out var list))
                {
                    list = new List<string>();
                    result[chosenLinear] = list;
                }
                if (!list.Contains(tag, StringComparer.Ordinal))
                    list.Add(tag);
            }

            return result.Count > 0 ? result : null;
        }

        private static void AppendExternalNameHintSuffix(ref string insText, uint linear, Dictionary<uint, List<string>> hints)
        {
            if (hints == null || !hints.TryGetValue(linear, out var names) || names == null || names.Count == 0)
                return;

            // Keep it compact and predictable.
            var joined = string.Join(", ", names.Take(3));
            if (names.Count > 3)
                joined += $", +{names.Count - 3}";
            insText += $" ; {joined}";
        }
    }
}
