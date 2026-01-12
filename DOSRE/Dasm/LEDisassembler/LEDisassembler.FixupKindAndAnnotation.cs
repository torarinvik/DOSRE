using System;
using System.Collections.Generic;
using System.Linq;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static bool TryGetFixupFieldStartDelta32(Instruction ins, LEFixup f, out int fieldDelta, out string kind)
        {
            fieldDelta = 0;
            kind = string.Empty;

            if (ins?.Bytes == null || ins.Bytes.Length < 4 || f == null)
                return false;

            var insStart = (uint)ins.Offset;
            var rawDelta = unchecked((int)(f.SiteLinear - insStart));
            if (rawDelta < 0 || rawDelta >= ins.Bytes.Length)
                return false;

            // Watcom/DOS4GW LE/LX fixup sites are not always aligned to the field start.
            // We have observed sites at the *end* of a 32-bit field (need to probe backwards)
            // and also sites earlier in the instruction than the field (need to probe forwards).
            var candidates = new[]
            {
                rawDelta,
                rawDelta - 1,
                rawDelta - 2,
                rawDelta - 3,
                rawDelta + 1,
                rawDelta + 2,
                rawDelta + 3,
            };

            foreach (var cand in candidates)
            {
                if (cand < 0)
                    continue;
                if (cand + 4 > ins.Bytes.Length)
                    continue;

                if (!TryClassifyFixupKind(ins, cand, out var k))
                    continue;

                if (k == "disp32" || k == "imm32" || k == "imm32?")
                {
                    fieldDelta = cand;
                    kind = k;
                    return true;
                }
            }

            return false;
        }

        private static List<LEFixup> GetFixupsForInstruction(List<LEFixup> fixups, Instruction ins, ref int idx)
        {
            if (fixups == null || fixups.Count == 0 || ins == null)
                return new List<LEFixup>(0);

            var insStart = (uint)ins.Offset;
            var insEnd = unchecked((uint)(insStart + (uint)ins.Length));

            // Advance past fixups that are below this instruction.
            while (idx < fixups.Count && fixups[idx].SiteLinear < insStart)
                idx++;

            if (idx >= fixups.Count)
                return new List<LEFixup>(0);

            var hit = new List<LEFixup>();
            var scan = idx;
            while (scan < fixups.Count)
            {
                var f = fixups[scan];
                if (f.SiteLinear >= insEnd)
                    break;
                hit.Add(f);
                scan++;
            }

            return hit;
        }

        private static string FormatFixupAnnotation(Instruction ins, List<LEFixup> fixupsHere, List<LEObject> objects)
        {
            if (fixupsHere == null || fixupsHere.Count == 0 || ins == null)
                return string.Empty;

            var insStart = (uint)ins.Offset;
            var parts = new List<string>();

            foreach (var f in fixupsHere)
            {
                var delta = unchecked((int)(f.SiteLinear - insStart));
                var kind = TryClassifyFixupKind(ins, delta, out var k) ? k : "unk";
                if (kind == "unk" && TryGetFixupFieldStartDelta32(ins, f, out var d2, out var k2))
                {
                    delta = d2;
                    kind = k2;
                }

                var targetStr = string.Empty;
                if (f.TargetType == 0 || f.TargetType == 3) // Internal
                {
                    targetStr = "[internal]";
                    if (f.TargetObject.HasValue && f.TargetOffset.HasValue)
                    {
                        targetStr += $" obj{f.TargetObject.Value}+0x{f.TargetOffset.Value:X}";
                        if (objects != null)
                        {
                            var oi = objects.FindIndex(o => o.Index == (uint)f.TargetObject.Value);
                            if (oi >= 0)
                            {
                                var baseAddr = objects[oi].BaseAddress;
                                var linear = baseAddr + (ulong)f.TargetOffset.Value;
                                targetStr += $" (linear 0x{linear:X8})";
                            }
                        }
                    }
                }
                else if (f.TargetType == 1 || f.TargetType == 2) // Import
                {
                    targetStr = $"[import {f.ImportModule ?? "?"}:{f.ImportProc ?? "?"}]";
                    if (f.Value32.HasValue)
                        targetStr += $" (site_val 0x{f.Value32.Value:X8})";
                }

                var v32 = f.Value32.HasValue && (f.TargetType == 0 || f.TargetType == 3) ? $" val32=0x{f.Value32.Value:X8}" : string.Empty;

                // Reduce noise for common 32-bit linear fixups.
                if (kind != "unk" || f.TargetOffset > 0)
                    parts.Add($"{kind} site+{delta} {targetStr} type=0x{f.Type:X2} flags=0x{f.Flags:X2}{v32}");
            }

            if (parts.Count == 0)
                return string.Empty;

            var distinct = parts.Distinct().ToList();
            const int maxShown = 3;
            if (distinct.Count <= maxShown)
                return string.Join(" | ", distinct);

            return string.Join(" | ", distinct.Take(maxShown)) + $" | (+{distinct.Count - maxShown} more)";
        }

        private static bool TryClassifyFixupKind(Instruction ins, int fixupDelta, out string kind)
        {
            kind = string.Empty;

            if (ins?.Bytes == null || ins.Bytes.Length == 0)
                return false;
            if (fixupDelta < 0 || fixupDelta >= ins.Bytes.Length)
                return false;

            var b = ins.Bytes;

            // Skip common prefixes
            var p = 0;
            while (p < b.Length)
            {
                var x = b[p];
                // operand-size, address-size, rep/lock, segment overrides
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65)
                {
                    p++;
                    continue;
                }
                break;
            }

            if (p >= b.Length)
                return false;

            static bool TryGetModrmAndSibDisp32(byte[] bytes, int modrmIndex, out int dispOff)
            {
                dispOff = 0;
                if (bytes == null)
                    return false;
                if (modrmIndex < 0 || modrmIndex >= bytes.Length)
                    return false;

                var modrm = bytes[modrmIndex];
                var mod = (modrm >> 6) & 0x3;
                var rm = modrm & 0x7;

                // mod=00 rm=101 => disp32
                if (mod == 0 && rm == 5)
                {
                    dispOff = modrmIndex + 1;
                    return dispOff + 4 <= bytes.Length;
                }

                // SIB present when rm==100 (in 32-bit addr mode)
                if (rm == 4)
                {
                    var sibIndex = modrmIndex + 1;
                    if (sibIndex >= bytes.Length)
                        return false;
                    var sib = bytes[sibIndex];
                    var baseReg = sib & 0x7;

                    // mod=00 base=101 => disp32
                    if (mod == 0 && baseReg == 5)
                    {
                        dispOff = sibIndex + 1;
                        return dispOff + 4 <= bytes.Length;
                    }

                    // mod=10 => disp32 after SIB (base+index+disp32)
                    if (mod == 2)
                    {
                        dispOff = sibIndex + 1;
                        return dispOff + 4 <= bytes.Length;
                    }

                    return false;
                }

                // mod=10 => disp32 after ModRM
                if (mod == 2)
                {
                    dispOff = modrmIndex + 1;
                    return dispOff + 4 <= bytes.Length;
                }

                return false;
            }

            static bool TryGetDispOffset(byte[] bytes, int modrmIndex, out int dispOff, out int dispSize)
            {
                dispOff = 0;
                dispSize = 0;
                if (bytes == null)
                    return false;
                if (modrmIndex < 0 || modrmIndex >= bytes.Length)
                    return false;

                var modrm = bytes[modrmIndex];
                var mod = (modrm >> 6) & 0x3;
                var rm = modrm & 0x7;

                var p0 = modrmIndex + 1;

                if (rm == 4)
                {
                    // SIB present
                    var sibIndex = p0;
                    if (sibIndex >= bytes.Length)
                        return false;
                    var sib = bytes[sibIndex];
                    var baseReg = sib & 0x7;

                    if (mod == 0 && baseReg == 5)
                    {
                        dispOff = sibIndex + 1;
                        dispSize = 4;
                        return dispOff + dispSize <= bytes.Length;
                    }
                    if (mod == 1)
                    {
                        dispOff = sibIndex + 1;
                        dispSize = 1;
                        return dispOff + dispSize <= bytes.Length;
                    }
                    if (mod == 2)
                    {
                        dispOff = sibIndex + 1;
                        dispSize = 4;
                        return dispOff + dispSize <= bytes.Length;
                    }

                    return false;
                }

                if (mod == 0 && rm == 5)
                {
                    dispOff = modrmIndex + 1;
                    dispSize = 4;
                    return dispOff + dispSize <= bytes.Length;
                }

                if (mod == 1)
                {
                    dispOff = modrmIndex + 1;
                    dispSize = 1;
                    return dispOff + dispSize <= bytes.Length;
                }

                if (mod == 2)
                {
                    dispOff = modrmIndex + 1;
                    dispSize = 4;
                    return dispOff + dispSize <= bytes.Length;
                }

                return false;
            }

            static bool TryGetImmOffsetAfterModrm(byte[] bytes, int modrmIndex, out int immOff)
            {
                immOff = 0;
                if (bytes == null)
                    return false;
                if (modrmIndex < 0 || modrmIndex >= bytes.Length)
                    return false;

                var modrm = bytes[modrmIndex];
                var mod = (modrm >> 6) & 0x3;
                var rm = modrm & 0x7;
                var p = modrmIndex + 1;

                // SIB
                if (rm == 4)
                {
                    if (p >= bytes.Length)
                        return false;
                    var sib = bytes[p];
                    var baseReg = sib & 0x7;
                    p++;

                    // disp sizes with SIB
                    if (mod == 0 && baseReg == 5)
                        p += 4;
                    else if (mod == 1)
                        p += 1;
                    else if (mod == 2)
                        p += 4;

                    immOff = p;
                    return immOff <= bytes.Length;
                }

                // disp sizes without SIB
                if (mod == 0 && rm == 5)
                    p += 4;
                else if (mod == 1)
                    p += 1;
                else if (mod == 2)
                    p += 4;

                immOff = p;
                return immOff <= bytes.Length;
            }

            var op0 = b[p];

            // MOV moffs: A0-A3 (disp32 right after opcode in 32-bit addr mode)
            if (op0 >= 0xA0 && op0 <= 0xA3)
            {
                var dispOff = p + 1;
                if (fixupDelta == dispOff)
                {
                    kind = "disp32";
                    return true;
                }
            }

            // MOV reg, imm32: B8-BF
            if (op0 >= 0xB8 && op0 <= 0xBF)
            {
                var immOff = p + 1;
                if (fixupDelta == immOff)
                {
                    kind = "imm32";
                    return true;
                }
            }

            // PUSH imm32: 68
            if (op0 == 0x68)
            {
                var immOff = p + 1;
                if (fixupDelta == immOff)
                {
                    kind = "imm32";
                    return true;
                }
            }

            // Two-byte opcodes
            var opLen = 1;
            byte op1 = 0;
            if (op0 == 0x0F)
            {
                if (p + 1 >= b.Length)
                    return false;
                op1 = b[p + 1];
                opLen = 2;
            }

            var opIndexEnd = p + opLen;
            if (opIndexEnd >= b.Length)
                return false;

            // Patterns with ModRM + disp32 + immediate (very common in DOS4GW code)
            // 80/81/83 grp1, C6/C7 mov r/m, imm
            if (op0 == 0x80 || op0 == 0x81 || op0 == 0x83 || op0 == 0xC6 || op0 == 0xC7)
            {
                var modrmIndex = opIndexEnd;
                if (TryGetDispOffset(b, modrmIndex, out var dispOffAny, out var dispSizeAny) && fixupDelta == dispOffAny)
                {
                    kind = dispSizeAny == 1 ? "disp8" : "disp32";
                    return true;
                }
                if (TryGetModrmAndSibDisp32(b, modrmIndex, out var dispOff) && fixupDelta == dispOff)
                {
                    kind = "disp32";
                    return true;
                }

                if (TryGetImmOffsetAfterModrm(b, modrmIndex, out var immOff))
                {
                    // Immediate offset depends on opcode.
                    if ((op0 == 0x81 || op0 == 0xC7) && fixupDelta == immOff)
                    {
                        kind = "imm32";
                        return true;
                    }
                    if ((op0 == 0x80 || op0 == 0x83 || op0 == 0xC6) && fixupDelta == immOff)
                    {
                        kind = "imm8";
                        return true;
                    }
                }
            }

            // Common reg/mem ops with disp32 only (no immediate): 8B/89/8D, etc.
            if (op0 == 0x8B || op0 == 0x89 || op0 == 0x8D)
            {
                var modrmIndex = opIndexEnd;
                if (TryGetDispOffset(b, modrmIndex, out var dispOffAny, out var dispSizeAny) && fixupDelta == dispOffAny)
                {
                    kind = dispSizeAny == 1 ? "disp8" : "disp32";
                    return true;
                }
                if (TryGetModrmAndSibDisp32(b, modrmIndex, out var dispOff) && fixupDelta == dispOff)
                {
                    kind = "disp32";
                    return true;
                }
            }

            // Fallback heuristic: if fixup hits the last 4 bytes, it’s likely an imm32 or disp32.
            if (ins.Bytes.Length >= 4 && fixupDelta == ins.Bytes.Length - 4)
            {
                kind = "imm32?";
                return true;
            }

            return false;
        }
    }
}
