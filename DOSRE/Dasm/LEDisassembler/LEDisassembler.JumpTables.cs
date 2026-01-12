using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
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

        private static bool TryGetJumpTableTargets(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int insIdx,
            Instruction ins,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            int maxEntries,
            out uint tableBase,
            out string indexReg,
            out List<uint> targets)
        {
            tableBase = 0;
            indexReg = string.Empty;
            targets = null;
            if (ins?.Bytes == null)
                return false;
            if (!TryParseIndirectJmpTable(ins.Bytes, out var disp, out var reg, out var scale))
                return false;

            indexReg = reg;

            if (TryResolveJumpTableTargets(instructions, insIndexByAddr, insIdx, ins, objects, objBytesByIndex, maxEntries, out var baseResolved, out var resolvedTargets, out var _))
            {
                tableBase = baseResolved;
                targets = resolvedTargets;
                return true;
            }

            return false;
        }

        internal static bool TryInferJumpTableSwitchBound(List<Instruction> instructions, int jmpIdx, string indexReg, out int caseCount, out uint defaultTarget)
        {
            caseCount = 0;
            defaultTarget = 0;
            if (instructions == null || jmpIdx <= 0 || string.IsNullOrWhiteSpace(indexReg))
                return false;

            // Pattern (common):
            //   cmp <reg>, <imm>
            //   ja  <default>
            //   jmp [<reg>*4 + table]
            // Allow small gaps.
            for (var back = 1; back <= 6; back++)
            {
                var idx = jmpIdx - back;
                if (idx < 0)
                    break;

                var t = InsText(instructions[idx]).Trim();
                if (!t.StartsWith("cmp ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var m = Regex.Match(
                    t,
                    @$"^cmp\s+{Regex.Escape(indexReg)}\s*,\s*(?:(?:byte|word|dword)\s+)?(?<imm>0x[0-9A-Fa-f]{{1,8}}|[0-9]+)\s*$",
                    RegexOptions.IgnoreCase);
                if (!m.Success)
                    continue;

                if (!TryParseHexUInt(m.Groups["imm"].Value, out var imm))
                    continue;

                // Find a following bounds-check jump between cmp and jmp.
                // Note: Disassemblers may render synonyms (e.g., jae == jnc == jnb).
                var inclusive = true;
                for (var fwd = idx + 1; fwd < jmpIdx && fwd <= idx + 3; fwd++)
                {
                    var jt = InsText(instructions[fwd]).Trim();
                    if (jt.StartsWith("ja ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jae ", StringComparison.OrdinalIgnoreCase) ||
                        jt.StartsWith("jg ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jge ", StringComparison.OrdinalIgnoreCase) ||
                        jt.StartsWith("jnc ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jnb ", StringComparison.OrdinalIgnoreCase))
                    {
                        // ja/jg => reg > imm ; valid cases: 0..imm (inclusive)
                        // jae/jge/jnc/jnb => reg >= imm ; valid cases: 0..imm-1 (exclusive)
                        inclusive = jt.StartsWith("ja ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jg ", StringComparison.OrdinalIgnoreCase);
                        if (TryGetRelativeBranchTarget(instructions[fwd], out var target, out var isCall) && !isCall)
                            defaultTarget = target;
                        break;
                    }
                }

                if (imm < 0x10000)
                {
                    var cc = inclusive ? checked((int)imm + 1) : checked((int)imm);
                    if (cc > 0)
                    {
                        caseCount = cc;
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
