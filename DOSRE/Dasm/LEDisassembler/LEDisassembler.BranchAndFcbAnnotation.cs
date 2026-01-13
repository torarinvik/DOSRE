using System;
using System.Collections.Generic;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static bool TryGetRelativeBranchTarget(Instruction ins, List<LEFixup> fixupsHere, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            if (ins == null || ins.Bytes == null || ins.Bytes.Length < 2)
                return false;

            // NEW: If we have a fixup at this site that provides a target, use it.
            // This is critical for LE because relative branches often encode dummy
            // targets (like 0x0 or un-relocated file offsets) that the loader replaces.
            if (fixupsHere != null && fixupsHere.Count > 0)
            {
                // Only consider fixups for actual relative control-flow instructions.
                // Otherwise we end up incorrectly treating arbitrary imm32 fixups (e.g. stack allocs)
                // as jump targets.
                int? dispStart = null;
                int dispSize = 0;

                if (ins.Bytes[0] == 0xE8 || ins.Bytes[0] == 0xE9)
                {
                    // CALL/JMP rel32
                    dispStart = 1;
                    dispSize = 4;
                }
                else if (ins.Bytes[0] == 0xEB || (ins.Bytes[0] >= 0x70 && ins.Bytes[0] <= 0x7F))
                {
                    // JMP rel8 / Jcc rel8
                    dispStart = 1;
                    dispSize = 1;
                }
                else if (ins.Bytes[0] == 0x0F && ins.Bytes.Length >= 2 && ins.Bytes[1] >= 0x80 && ins.Bytes[1] <= 0x8F)
                {
                    // Jcc rel32
                    dispStart = 2;
                    dispSize = 4;
                }

                if (dispStart == null)
                    return false;

                var dispAbsStart = (uint)ins.Offset + (uint)dispStart.Value;
                var dispAbsEndExclusive = dispAbsStart + (uint)dispSize;

                foreach (var fix in fixupsHere)
                {
                    if (fix.TargetLinear.HasValue && (fix.Type == 0x05 || fix.Type == 0x06 || fix.Type == 0x07))
                    {
                        // Only accept fixups that overlap the displacement field of this relative branch.
                        if (fix.SiteLinear >= dispAbsStart && fix.SiteLinear < dispAbsEndExclusive)
                        {
                            target = fix.TargetLinear.Value;
                            isCall = ins.Mnemonic == ud_mnemonic_code.UD_Icall;
                            return true;
                        }
                    }
                }
            }

            // Fallback to standard relativo logic if no fixup resolved it.
            return TryGetRelativeBranchTarget(ins, out target, out isCall);
        }

        private static bool TryGetRelativeBranchTarget(Instruction ins, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            if (ins == null || ins.Bytes == null || ins.Bytes.Length < 2)
                return false;

            // CALL rel32: E8 xx xx xx xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Icall && ins.Bytes[0] == 0xE8 && ins.Bytes.Length >= 5)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 1);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                isCall = true;
                return true;
            }

            // JMP rel32: E9 xx xx xx xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ijmp && ins.Bytes[0] == 0xE9 && ins.Bytes.Length >= 5)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 1);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // JMP rel8: EB xx
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ijmp && ins.Bytes[0] == 0xEB && ins.Bytes.Length >= 2)
            {
                var rel = unchecked((sbyte)ins.Bytes[1]);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // Jcc rel8: 70-7F xx
            if (MnemonicGroupings.JumpGroup.Contains(ins.Mnemonic) && ins.Bytes[0] >= 0x70 && ins.Bytes[0] <= 0x7F &&
                ins.Bytes.Length >= 2)
            {
                var rel = unchecked((sbyte)ins.Bytes[1]);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            // Jcc rel32: 0F 80-8F xx xx xx xx
            if (MnemonicGroupings.JumpGroup.Contains(ins.Mnemonic) && ins.Bytes[0] == 0x0F && ins.Bytes.Length >= 6 &&
                ins.Bytes[1] >= 0x80 && ins.Bytes[1] <= 0x8F)
            {
                var rel = BitConverter.ToInt32(ins.Bytes, 2);
                var next = unchecked((long)ins.Offset + ins.Length);
                target = unchecked((uint)(next + rel));
                return true;
            }

            return false;
        }

        private static string TryAnnotateFcb(uint? linearAddr, Dictionary<uint, string> stringSymbols, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex)
        {
            if (!linearAddr.HasValue) return string.Empty;

            foreach (var obj in objects)
            {
                if (linearAddr >= obj.RelocBaseAddr && linearAddr < obj.RelocBaseAddr + obj.VirtualSize)
                {
                    if (objBytesByIndex.TryGetValue(obj.ObjectNumber, out var bytes))
                    {
                        uint relativeOffset = linearAddr.Value - obj.RelocBaseAddr;
                        if (relativeOffset + 12 <= bytes.Length)
                        {
                            return MZDisassembler.TryFormatFcbDetail(relativeOffset, bytes);
                        }
                    }
                    break;
                }
            }

            return string.Empty;
        }
    }
}
