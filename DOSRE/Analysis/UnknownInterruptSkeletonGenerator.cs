using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace DOSRE.Analysis
{
    public static class UnknownInterruptSkeletonGenerator
    {
        private static readonly Regex LineRegex = new Regex(
            @"^INT\s+0x(?<int>[0-9A-Fa-f]{2})(?:\s+AH=0x(?<ah>[0-9A-Fa-f]{2}))?(?:\s+AX=0x(?<ax>[0-9A-Fa-f]{4}))?\s*$",
            RegexOptions.Compiled);

        public static void Generate(string inputPath, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(inputPath))
                throw new Exception("Error: missing input path");
            if (string.IsNullOrWhiteSpace(outputPath))
                throw new Exception("Error: missing output path");
            if (!File.Exists(inputPath))
                throw new Exception($"Error: input file not found: {inputPath}");

            var lines = File.ReadAllLines(inputPath)
                .Select(l => (l ?? string.Empty).Trim())
                .Where(l => !string.IsNullOrEmpty(l))
                .Distinct(StringComparer.Ordinal)
                .ToList();

            var byInt = new SortedDictionary<byte, IntGroup>();

            foreach (var line in lines)
            {
                var m = LineRegex.Match(line);
                if (!m.Success)
                    continue;

                var intNo = Convert.ToByte(m.Groups["int"].Value, 16);
                if (!byInt.TryGetValue(intNo, out var g))
                {
                    g = new IntGroup();
                    byInt[intNo] = g;
                }

                if (m.Groups["ah"].Success)
                    g.AhCodes.Add(Convert.ToByte(m.Groups["ah"].Value, 16));
                if (m.Groups["ax"].Success)
                    g.AxCodes.Add(Convert.ToUInt16(m.Groups["ax"].Value, 16));
            }

            var interruptEntries = new List<object>();
            foreach (var kv in byInt)
            {
                var intNo = kv.Key;
                var g = kv.Value;

                string selector;
                var functions = new List<object>();

                if (g.AxCodes.Count > 0)
                {
                    selector = "AX";
                    foreach (var ax in g.AxCodes.OrderBy(x => x))
                        functions.Add(new { code = $"0x{ax:X4}", name = "", @params = new string[0], returns = new string[0] });

                    // If both exist, keep AH values too as 0x00AH under AX so nothing is lost.
                    foreach (var ah in g.AhCodes.OrderBy(x => x))
                        functions.Add(new { code = $"0x{ah:X2}", name = "", @params = new string[0], returns = new string[0] });
                }
                else if (g.AhCodes.Count > 0)
                {
                    selector = "AH";
                    foreach (var ah in g.AhCodes.OrderBy(x => x))
                        functions.Add(new { code = $"0x{ah:X2}", name = "", @params = new string[0], returns = new string[0] });
                }
                else
                {
                    selector = string.Empty;
                }

                interruptEntries.Add(new
                {
                    @int = $"0x{intNo:X2}",
                    name = "",
                    selector,
                    functions
                });
            }

            var root = new
            {
                meta = new
                {
                    description = "Skeleton interrupt pack generated from dosre.unknown-ints.txt (fill in names/params/returns).",
                    notes = new[]
                    {
                        "This file contains only interrupt numbers and observed selector values (AH/AX) from analyzed binaries.",
                        "Populate names/params/returns using your own references.",
                        "If both AH and AX were seen for the same interrupt, codes are emitted under selector AX and AH codes are included as 0x00AH-style values for convenience."
                    }
                },
                interrupts = interruptEntries
            };

            var json = JsonConvert.SerializeObject(root, Formatting.Indented);
            File.WriteAllText(outputPath, json);
        }

        private sealed class IntGroup
        {
            public readonly HashSet<byte> AhCodes = new HashSet<byte>();
            public readonly HashSet<ushort> AxCodes = new HashSet<ushort>();
        }
    }
}
