using System;
using System.Collections.Generic;
using System.Linq;
using DOSRE.Analysis;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static void HeuristicLabelFunctions(List<Instruction> instructions, HashSet<uint> starts, LeAnalysis analysis)
        {
            if (instructions == null || starts == null || analysis == null)
                return;

            var sortedStarts = starts.OrderBy(s => s).ToList();
            var insIndexByAddr = new Dictionary<uint, int>();
            for (var i = 0; i < instructions.Count; i++)
                insIndexByAddr[(uint)instructions[i].Offset] = i;

            for (var i = 0; i < sortedStarts.Count; i++)
            {
                var startAddr = sortedStarts[i];
                if (analysis.ExportedNames.ContainsKey(startAddr))
                    continue;

                if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                    continue;

                var endIdx = instructions.Count;
                if (i + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[i + 1], out var nextIdx))
                    endIdx = nextIdx;

                // Only scan first 16 instructions for high-level signature.
                var scanLimit = Math.Min(endIdx, startIdx + 16);
                var body = new List<string>();
                for (var j = startIdx; j < scanLimit; j++)
                    body.Add(InsText(instructions[j]).ToLowerInvariant());

                var name = TryMatchLibrarySignature(body);
                if (!string.IsNullOrEmpty(name))
                {
                    analysis.ExportedNames[startAddr] = name;
                }
            }
        }

        private static string TryMatchLibrarySignature(List<string> body)
        {
            if (body == null || body.Count == 0)
                return null;

            // Pattern: mov eax, 0x4c00; int 0x21
            // Most DOS4GW library functions for exit look like this.
            if (MatchesPattern(body, "mov eax, 0x00004c", "int 0x21") || 
                MatchesPattern(body, "mov ax, 0x4c", "int 0x21") ||
                MatchesPattern(body, "mov ah, 0x4c", "int 0x21"))
                return "__exit";

            // Pattern: mov ah, 0x2c; int 0x21
            if (MatchesPattern(body, "mov ah, 0x2c", "int 0x21"))
                return "__get_time";

            // Pattern: mov ah, 0x2a; int 0x21
            if (MatchesPattern(body, "mov ah, 0x2a", "int 0x21"))
                return "__get_date";

            // Pattern: mov ah, 0x30; int 0x21
            if (MatchesPattern(body, "mov ah, 0x30", "int 0x21"))
                return "__get_dos_version";

            // Pattern: mov ax, 0x35XX; int 0x21 (Get Interrupt Vector)
            if (MatchesPattern(body, "mov ah, 0x35", "int 0x21"))
                return "__get_interrupt_vector";

            // Pattern: mov ax, 0x25XX; int 0x21 (Set Interrupt Vector)
            if (MatchesPattern(body, "mov ah, 0x25", "int 0x21"))
                return "__set_interrupt_vector";

            // Pattern: mov ah, 0x3d; int 0x21 (Open File)
            if (MatchesPattern(body, "mov ah, 0x3d", "int 0x21"))
                return "__open_file";

            // Pattern: mov ah, 0x3e; int 0x21 (Close File)
            if (MatchesPattern(body, "mov ah, 0x3e", "int 0x21"))
                return "__close_file";

            // Pattern: mov ah, 0x3f; int 0x21 (Read File)
            if (MatchesPattern(body, "mov ah, 0x3f", "int 0x21"))
                return "__read_file";

            // Pattern: mov ah, 0x40; int 0x21 (Write File)
            if (MatchesPattern(body, "mov ah, 0x40", "int 0x21"))
                return "__write_file";

            // Pattern: mov ax, 0x0800; int 0x31 (Physical Address Mapping)
            if (MatchesPattern(body, "mov ax, 0x0800", "int 0x31") ||
                MatchesPattern(body, "mov eax, 0x00000800", "int 0x31"))
                return "__dpmi_map_physical";

            // Pattern: mov ax, 0x0000; int 0x31 (Allocate LDT Descriptor)
            if (MatchesPattern(body, "mov ax, 0x0000", "int 0x31") ||
                MatchesPattern(body, "mov eax, 0x00000000", "int 0x31"))
                return "__dpmi_allocate_ldt_descriptors";

            // Pattern: mov ax, 0x0501; int 0x31 (Allocate Memory Block)
            if (MatchesPattern(body, "mov ax, 0x0501", "int 0x31") ||
                MatchesPattern(body, "mov eax, 0x00000501", "int 0x31"))
                return "__dpmi_allocate_memory_block";

            // Pattern: mov ax, 0x0502; int 0x31 (Free Memory Block)
            if (MatchesPattern(body, "mov ax, 0x0502", "int 0x31") ||
                MatchesPattern(body, "mov eax, 0x00000502", "int 0x31"))
                return "__dpmi_free_memory_block";

            // Watcom stack check pattern:
            //   cmp esp, [....]
            //   jae ....
            //   call __STK
            if (MatchesPattern(body, "cmp esp", "jae", "call"))
            {
                // This is likely the stack overflow handler.
                // We don't name the function itself __STK, but if it calls it...
            }

            return null;
        }

        private static bool MatchesPattern(List<string> body, params string[] subtexts)
        {
            var lastIdx = -1;
            foreach (var s in subtexts)
            {
                var found = false;
                for (var i = lastIdx + 1; i < body.Count; i++)
                {
                    if (body[i].Contains(s, StringComparison.OrdinalIgnoreCase))
                    {
                        lastIdx = i;
                        found = true;
                        break;
                    }
                }
                if (!found) return false;
            }
            return true;
        }
    }
}
