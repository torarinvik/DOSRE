using System;
using System.Collections.Generic;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string TryAnnotateJumpTableSwitchBounds(List<Instruction> instructions, int insLoopIndex, Instruction ins)
        {
            if (instructions == null || insLoopIndex < 0 || insLoopIndex >= instructions.Count)
                return string.Empty;
            if (ins?.Bytes == null)
                return string.Empty;

            if (!TryParseIndirectJmpTable(ins.Bytes, out var _, out var indexReg, out var scale))
                return string.Empty;

            if (!TryInferJumpTableSwitchBound(instructions, insLoopIndex, indexReg, out var cases, out var def))
                return string.Empty;

            // Keep it tight: just range + default.
            var shownCases = Math.Min(256, Math.Max(1, cases));
            var defText = def != 0 ? $"loc_{def:X8}" : "(unknown)";
            return $"SWITCH: {indexReg} cases=0..{shownCases - 1} default={defText}";
        }
    }
}
