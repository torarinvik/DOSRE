using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace MBBSDASM.Renderer.impl
{
    /// <summary>
    /// Post-processing helper: find repeated straight-line instruction chunks and replace them with macros.
    ///
    /// This operates on the text output (not binary) and is intended to improve readability when browsing.
    /// </summary>
    public static class MacroDeduper
    {
        // Matches a disassembly line with a byte column followed by an instruction string.
        // Works for both LE lines ("000A5E64h F7E7 ...") and NE lines (which contain bytes before the instruction too).
        private static readonly Regex InstructionLineRegex =
            new Regex(@"^(?<prefix>.*?\b)(?<bytes>[0-9A-F]{2,64})\s+(?<ins>.+)$", RegexOptions.Compiled);

        private static readonly HashSet<string> ControlFlowMnemonics = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "call", "jmp", "ret", "retn", "retf",
            "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz",
            "je", "jz", "jne", "jnz", "jg", "jge", "jl", "jle",
            "jo", "jno", "jp", "jpe", "jnp", "jpo", "js", "jns",
            "loop", "loope", "loopne", "loopnz", "loopz"
        };

        public static string Apply(string content, int windowLines = 8, int minOccurrences = 3)
        {
            if (string.IsNullOrEmpty(content))
                return content;
            if (windowLines <= 1 || minOccurrences <= 1)
                return content;

            var lines = SplitLines(content, out var newline);

            // Extract instruction-only signature for each line.
            var insText = new string[lines.Count];
            var isInstruction = new bool[lines.Count];
            var safeForMacro = new bool[lines.Count];

            for (var i = 0; i < lines.Count; i++)
            {
                if (TryGetInstructionText(lines[i], out var instruction))
                {
                    isInstruction[i] = true;
                    insText[i] = instruction;
                    safeForMacro[i] = IsSafeForMacro(instruction);
                }
            }

            // Count occurrences of each window signature.
            var occurrences = new Dictionary<string, List<int>>();
            for (var i = 0; i + windowLines <= lines.Count; i++)
            {
                var ok = true;
                for (var j = 0; j < windowLines; j++)
                {
                    if (!isInstruction[i + j] || !safeForMacro[i + j])
                    {
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                    continue;

                var sig = string.Join("\n", insText.Skip(i).Take(windowLines));
                if (!occurrences.TryGetValue(sig, out var list))
                    occurrences[sig] = list = new List<int>();
                list.Add(i);
            }

            // Pick the best candidate (longest*count) and apply greedily.
            var candidates = occurrences
                .Where(kvp => kvp.Value.Count >= minOccurrences)
                .OrderByDescending(kvp => kvp.Value.Count)
                .ThenByDescending(kvp => kvp.Key.Length)
                .ToList();

            if (candidates.Count == 0)
                return content;

            var used = new bool[lines.Count];
            var macroDefs = new StringBuilder();
            var replacements = new Dictionary<int, (int len, string macroName)>();
            var macroIndex = 1;

            foreach (var cand in candidates)
            {
                var starts = cand.Value;
                var chosen = new List<int>();
                foreach (var s in starts)
                {
                    // no overlap
                    var overlaps = false;
                    for (var k = 0; k < windowLines; k++)
                    {
                        if (used[s + k])
                        {
                            overlaps = true;
                            break;
                        }
                    }

                    if (!overlaps)
                        chosen.Add(s);
                }

                if (chosen.Count < minOccurrences)
                    continue;

                var macroName = $"MACRO_DUP_{macroIndex:000}";
                macroIndex++;

                // Define macro
                macroDefs.AppendLine($"{macroName} MACRO");
                foreach (var ins in cand.Key.Split('\n'))
                    macroDefs.AppendLine($"    {ins}");
                macroDefs.AppendLine("ENDM");
                macroDefs.AppendLine();

                foreach (var s in chosen)
                {
                    for (var k = 0; k < windowLines; k++)
                        used[s + k] = true;
                    replacements[s] = (windowLines, macroName);
                }
            }

            if (macroDefs.Length == 0 || replacements.Count == 0)
                return content;

            // Build output with replacements.
            var outLines = new List<string>();

            // Insert macros after the initial header block (leading ';' lines), or at top.
            var insertAt = 0;
            while (insertAt < lines.Count && (lines[insertAt].StartsWith(";") || string.IsNullOrWhiteSpace(lines[insertAt])))
                insertAt++;

            for (var i = 0; i < lines.Count;)
            {
                if (i == insertAt)
                {
                    outLines.Add(";-------------------------------------------");
                    outLines.Add("; Auto-generated macros (duplicate chunks)");
                    outLines.Add(";-------------------------------------------");
                    outLines.AddRange(SplitLines(macroDefs.ToString(), out _));
                }

                if (replacements.TryGetValue(i, out var rep))
                {
                    outLines.Add($"{rep.macroName}");
                    i += rep.len;
                    continue;
                }

                outLines.Add(lines[i]);
                i++;
            }

            return string.Join(newline, outLines);
        }

        private static bool TryGetInstructionText(string line, out string instruction)
        {
            instruction = string.Empty;

            if (string.IsNullOrWhiteSpace(line))
                return false;
            if (line.StartsWith(";") || line.EndsWith(":"))
                return false;

            var m = InstructionLineRegex.Match(line.TrimEnd('\r', '\n'));
            if (!m.Success)
                return false;

            // Reject if bytes group looks like it actually captured an address suffix.
            var ins = m.Groups["ins"].Value.Trim();
            if (string.IsNullOrEmpty(ins))
                return false;

            instruction = ins;
            return true;
        }

        private static bool IsSafeForMacro(string instruction)
        {
            var mnemonic = instruction.TrimStart().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrEmpty(mnemonic))
                return false;

            return !ControlFlowMnemonics.Contains(mnemonic);
        }

        private static List<string> SplitLines(string content, out string newline)
        {
            newline = content.Contains("\r\n") ? "\r\n" : "\n";
            var parts = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            return parts.ToList();
        }
    }
}
