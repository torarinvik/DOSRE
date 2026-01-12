using System;
using System.Collections.Generic;
using DOSRE.Analysis;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string TryAnnotateInterrupt(List<Instruction> instructions, int idx, Dictionary<uint, string> stringSymbols, Dictionary<uint, string> stringPreview, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            var ins = instructions[idx];
            if (!TryGetIntNumber(ins, out var intNo))
                return string.Empty;

            // Database-driven descriptions first.
            byte? dbAh = TryResolveAhBefore(instructions, idx);
            ushort? dbAx = TryResolveAxBefore(instructions, idx);

            var edxOperand = TryResolveEdxBefore(instructions, idx);
            var esiOperand = TryResolveEsiBefore(instructions, idx);

            var edxDetail = TryFormatPointerDetail("EDX", edxOperand, stringSymbols, stringPreview, objects, objBytesByIndex);
            var esiDetail = TryFormatPointerDetail("ESI", esiOperand, stringSymbols, stringPreview, objects, objBytesByIndex);

            string db;
            if (DosInterruptDatabase.Instance.TryDescribe(intNo, dbAh, dbAx, out db) && !string.IsNullOrEmpty(db))
            {
                // Preserve existing prefixing style for readability in LE output.
                if (intNo == 0x21)
                {
                    var extra = string.Empty;
                    if (dbAh.HasValue)
                    {
                        var ah = dbAh.Value;
                        // FCB functions
                        if (ah == 0x0F || ah == 0x10 || ah == 0x11 || ah == 0x12 || ah == 0x13 || ah == 0x16 || ah == 0x17 ||
                            ah == 0x21 || ah == 0x22 || ah == 0x23 || ah == 0x24 || ah == 0x27 || ah == 0x28)
                        {
                            uint? edxVal = null;
                            if (TryParseHexUInt(edxOperand, out var v)) edxVal = v;
                            var fcb = TryAnnotateFcb(edxVal, stringSymbols, objects, objBytesByIndex);
                            if (!string.IsNullOrEmpty(fcb))
                                extra = " ; " + fcb;
                        }

                        if (string.IsNullOrEmpty(extra))
                        {
                            // DX/EDX based
                            if (ah == 0x09 || ah == 0x0A || ah == 0x1A || ah == 0x39 || ah == 0x3A || ah == 0x3B || ah == 0x3C ||
                                ah == 0x3D || ah == 0x3F || ah == 0x40 || ah == 0x41 || ah == 0x43 || ah == 0x4B ||
                                ah == 0x4E || ah == 0x56 || ah == 0x5A || ah == 0x5B)
                            {
                                if (!string.IsNullOrEmpty(edxDetail))
                                    extra = " ; " + edxDetail;
                            }
                            // SI/ESI based
                            if (ah == 0x47 || ah == 0x6C || ah == 0x71)
                            {
                                if (!string.IsNullOrEmpty(esiDetail))
                                    extra = " ; " + esiDetail;
                            }
                        }
                    }
                    return "INT21: " + db + extra;
                }
                if (intNo == 0x31)
                    return "INT31: " + db;
                return "INT: " + db;
            }

            // Opt-in: record unknown interrupt usage for building local packs.
            UnknownInterruptRecorder.Record(intNo, dbAh, dbAx);

            // BIOS/DOS/high-level tags
            if (intNo == 0x10)
                return "INT: BIOS video int 10h";
            if (intNo == 0x16)
                return "INT: BIOS keyboard int 16h";
            if (intNo == 0x33)
                return "INT: Mouse int 33h";

            if (intNo == 0x21)
            {
                var ah = TryResolveAhBefore(instructions, idx);
                if (!ah.HasValue)
                    return "INT21: DOS";

                var name = DescribeInt21Ah(ah.Value);
                var baseText = string.IsNullOrEmpty(name) ? $"INT21: AH=0x{ah.Value:X2}" : $"INT21: {name} (AH=0x{ah.Value:X2})";

                // Add DS:EDX best-effort pointer detail for common calls.
                var val = ah.Value;
                if (val == 0x09 || val == 0x11 || val == 0x12 || val == 0x13 || val == 0x17 || val == 0x1A ||
                    val == 0x27 || val == 0x28 || val == 0x39 || val == 0x3A || val == 0x3B || val == 0x3C ||
                    val == 0x3D || val == 0x3F || val == 0x40 || val == 0x41 || val == 0x43 || val == 0x47 ||
                    val == 0x4B || val == 0x4E || val == 0x56 || val == 0x5A || val == 0x5B || val == 0x6C)
                {
                    if (!string.IsNullOrEmpty(edxDetail))
                        baseText += " ; " + edxDetail;
                }

                return baseText;
            }

            if (intNo == 0x31)
            {
                var ax = TryResolveAxBefore(instructions, idx);
                if (!ax.HasValue)
                    return "INT31: DPMI";

                var name = DescribeInt31Ax(ax.Value);
                return string.IsNullOrEmpty(name) ? $"INT31: AX=0x{ax.Value:X4}" : $"INT31: {name} (AX=0x{ax.Value:X4})";
            }

            return $"INT: 0x{intNo:X2}";
        }

        private static bool TryGetIntNumber(Instruction ins, out byte intNo)
        {
            intNo = 0;
            if (ins?.Bytes == null || ins.Bytes.Length < 2)
                return TryGetIntNumberFromText(ins, out intNo);

            var b = ins.Bytes;
            var p = 0;
            while (p < b.Length)
            {
                var x = b[p];
                // Common prefixes (same set as elsewhere)
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65)
                {
                    p++;
                    continue;
                }
                break;
            }

            if (p + 1 >= b.Length)
                return TryGetIntNumberFromText(ins, out intNo);
            if (b[p] != 0xCD)
                return TryGetIntNumberFromText(ins, out intNo);

            intNo = b[p + 1];
            return true;
        }

        private static bool TryGetIntNumberFromText(Instruction ins, out byte intNo)
        {
            intNo = 0;
            var t = ins?.ToString()?.Trim();
            if (string.IsNullOrEmpty(t))
                return false;

            // SharpDisasm commonly renders as: "int 0x21".
            if (!t.StartsWith("int ", StringComparison.OrdinalIgnoreCase))
                return false;

            var op = t.Substring(4).Trim();
            if (op.Length == 0)
                return false;

            // Ignore int3/int1 special mnemonics that may show up as "int3" etc.
            if (op.Equals("3", StringComparison.OrdinalIgnoreCase) || op.Equals("0x03", StringComparison.OrdinalIgnoreCase))
            {
                intNo = 0x03;
                return true;
            }

            // Accept 0xNN, NNh, or decimal.
            if (op.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (!byte.TryParse(op.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out intNo))
                    return false;
                return true;
            }

            if (op.EndsWith("h", StringComparison.OrdinalIgnoreCase))
            {
                var hex = op.Substring(0, op.Length - 1);
                if (!byte.TryParse(hex, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out intNo))
                    return false;
                return true;
            }

            return byte.TryParse(op, out intNo);
        }

        private static byte? TryResolveAhBefore(List<Instruction> instructions, int idx)
        {
            // Look back a short window within the same straight-line region.
            for (var i = idx - 1; i >= 0 && i >= idx - 20; i--)
            {
                var ins = instructions[i];
                var b = ins.Bytes;
                if (b == null || b.Length == 0)
                    continue;

                // Barrier on control flow.
                var t = InsText(ins);
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov ah, imm8  => B4 ib
                if (b.Length >= 2 && b[0] == 0xB4)
                    return b[1];

                // mov ax, imm16  => 66 B8 iw
                if (b.Length >= 4 && b[0] == 0x66 && b[1] == 0xB8)
                {
                    var ax = (ushort)(b[2] | (b[3] << 8));
                    return (byte)((ax >> 8) & 0xFF);
                }

                // mov eax, imm32 => B8 id
                if (b.Length >= 5 && b[0] == 0xB8)
                {
                    var eax = (uint)(b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));
                    return (byte)((eax >> 8) & 0xFF);
                }

                // xor ah, ah => 30 E4
                if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xE4)
                    return 0x00;
            }

            return null;
        }

        private static ushort? TryResolveAxBefore(List<Instruction> instructions, int idx)
        {
            for (var i = idx - 1; i >= 0 && i >= idx - 24; i--)
            {
                var ins = instructions[i];
                var b = ins.Bytes;
                if (b == null || b.Length == 0)
                    continue;

                var t = InsText(ins);
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov ax, imm16 => 66 B8 iw
                if (b.Length >= 4 && b[0] == 0x66 && b[1] == 0xB8)
                    return (ushort)(b[2] | (b[3] << 8));

                // mov eax, imm32 => B8 id (use low 16)
                if (b.Length >= 5 && b[0] == 0xB8)
                {
                    var eax = (uint)(b[1] | (b[2] << 8) | (b[3] << 16) | (b[4] << 24));
                    return (ushort)(eax & 0xFFFF);
                }
            }

            return null;
        }

        private static string DescribeInt21Ah(byte ah)
        {
            // Common DOS services (not exhaustive)
            switch (ah)
            {
                case 0x09: return "Display string ($-terminated)";
                case 0x0A: return "Buffered keyboard input";
                case 0x1A: return "Set DTA";
                case 0x2F: return "Get DTA";
                case 0x25: return "Set interrupt vector";
                case 0x35: return "Get interrupt vector";
                case 0x3C: return "Create file";
                case 0x3D: return "Open file";
                case 0x3E: return "Close file";
                case 0x3F: return "Read file/handle";
                case 0x40: return "Write file/handle";
                case 0x41: return "Delete file";
                case 0x42: return "Lseek";
                case 0x43: return "Get/Set file attributes";
                case 0x44: return "IOCTL";
                case 0x47: return "Get current directory";
                case 0x48: return "Allocate memory";
                case 0x49: return "Free memory";
                case 0x4A: return "Resize memory block";
                case 0x4B: return "Exec";
                case 0x4C: return "Terminate process";
                case 0x4E: return "Find first";
                case 0x4F: return "Find next";
                case 0x56: return "Rename file";
                case 0x57: return "Get/Set file date/time";
                default:
                    return string.Empty;
            }
        }

        private static string DescribeInt31Ax(ushort ax)
        {
            // DPMI services (best-effort common subset)
            switch (ax)
            {
                case 0x0000: return "Allocate LDT descriptors";
                case 0x0001: return "Free LDT descriptor";
                case 0x0002: return "Segment to descriptor";
                case 0x0003: return "Get selector increment value";
                case 0x0006: return "Get segment base address";
                case 0x0007: return "Set segment base address";
                case 0x0008: return "Set segment limit";
                case 0x0009: return "Set descriptor access rights";
                case 0x000A: return "Create alias descriptor";
                case 0x0100: return "Allocate DOS memory block";
                case 0x0101: return "Free DOS memory block";
                case 0x0102: return "Resize DOS memory block";
                case 0x0200: return "Get real-mode interrupt vector";
                case 0x0201: return "Set real-mode interrupt vector";
                case 0x0204: return "Get exception handler vector";
                case 0x0205: return "Set exception handler vector";
                case 0x0300: return "Simulate real-mode interrupt";
                case 0x0301: return "Call real-mode procedure (far ret)";
                case 0x0302: return "Call real-mode procedure (iret)";
                case 0x0303: return "Allocate real-mode callback";
                case 0x0304: return "Free real-mode callback";
                case 0x0400: return "Get DPMI version";
                case 0x0501: return "Allocate memory block";
                case 0x0502: return "Free memory block";
                case 0x0503: return "Resize memory block";
                case 0x0600: return "Lock linear region";
                case 0x0601: return "Unlock linear region";
                case 0x0800: return "Physical address mapping";
                default:
                    return string.Empty;
            }
        }
    }
}
