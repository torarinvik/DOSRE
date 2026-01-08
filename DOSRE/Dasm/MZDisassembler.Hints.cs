using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
        private static string TryGetIndirectCallHint(Instruction ins, IReadOnlyList<Instruction> instructions, int index)
        {
            var b = ins.Bytes;
            if (b == null || b.Length < 2)
                return null;

            // Indirect CALL (often a function pointer / callback)
            // FF /2 = CALL r/m16 (near), FF /3 = CALL m16:16 (far)
            if (b[0] != 0xFF)
                return null;

            var modrm = b[1];
            var reg = (modrm >> 3) & 0x07;
            if (reg != 2 && reg != 3)
                return null;

            var text = ins.ToString();
            var callIdx = text.IndexOf("call", StringComparison.OrdinalIgnoreCase);
            var op = callIdx >= 0 ? text[(callIdx + 4)..].Trim() : text;
            if (string.IsNullOrEmpty(op))
                op = "?";

            var pushes = CountImmediatelyPrecedingPushes(instructions, index, max: 6);
            var argsSuffix = pushes > 0 ? $" (args~{pushes})" : string.Empty;

            return reg == 3
                ? $"INDIRECT FAR CALL via {op}{argsSuffix}"
                : $"INDIRECT CALL via {op}{argsSuffix}";
        }

        private static int CountImmediatelyPrecedingPushes(IReadOnlyList<Instruction> instructions, int index, int max)
        {
            if (instructions == null || index <= 0 || max <= 0)
                return 0;

            var count = 0;
            for (var i = index - 1; i >= 0 && count < max; i--)
            {
                var prior = instructions[i];
                if (prior == null)
                    break;

                // Treat any PUSH as an argument push (best-effort).
                // Stop at the first non-push to keep this conservative.
                if (prior.Mnemonic == ud_mnemonic_code.UD_Ipush)
                {
                    count++;
                    continue;
                }

                break;
            }

            return count;
        }

        private static string TryGetPackedNibbleShiftHint(IReadOnlyList<Instruction> instructions, int index)
        {
            // Pattern (seen in PERFORM):
            //   xor bx,bx
            //   mov bl,ah
            //   mov cl,4
            //   shr bx,cl
            //   shl ax,cl
            // Interpretable as splitting a packed 4:12 value:
            //   BX = (AH >> 4)
            //   AX = (AX << 4)
            if (instructions == null || index < 4)
                return null;

            static bool BytesEq(byte[] b, params byte[] pat)
            {
                if (b == null || b.Length != pat.Length)
                    return false;
                for (var i = 0; i < pat.Length; i++)
                {
                    if (b[i] != pat[i])
                        return false;
                }
                return true;
            }

            var b0 = instructions[index - 4].Bytes;
            var b1 = instructions[index - 3].Bytes;
            var b2 = instructions[index - 2].Bytes;
            var b3 = instructions[index - 1].Bytes;
            var b4 = instructions[index].Bytes;

            if (BytesEq(b0, 0x33, 0xDB) &&       // xor bx,bx
                BytesEq(b1, 0x8A, 0xDC) &&       // mov bl,ah
                BytesEq(b2, 0xB1, 0x04) &&       // mov cl,4
                BytesEq(b3, 0xD3, 0xEB) &&       // shr bx,cl
                BytesEq(b4, 0xD3, 0xE0))         // shl ax,cl
            {
                return "PACKED SPLIT: BX = AH>>4; AX <<= 4 (4:12 split)";
            }

            return null;
        }

        private static string TryGetHigherLevelHint(
            List<Instruction> instructions,
            int index,
            byte? ah, byte? al,
            ushort? ax, ushort? bx, ushort? cx, ushort? dx,
            ushort? si, ushort? di,
            ushort? ds, ushort? es)
        {
            var ins = instructions[index];
            var prev = index > 0 ? instructions[index - 1] : null;
            var b = ins.Bytes;
            if (b == null || b.Length == 0) return null;
            var text = ins.ToString();

            // LDS/LES/LFS/LGS/LSS far pointer loads
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ilds || ins.Mnemonic == ud_mnemonic_code.UD_Iles ||
                ins.Mnemonic == ud_mnemonic_code.UD_Ilfs || ins.Mnemonic == ud_mnemonic_code.UD_Ilgs || ins.Mnemonic == ud_mnemonic_code.UD_Ilss)
            {
                var sreg = ins.Mnemonic switch {
                    ud_mnemonic_code.UD_Ilds => "DS",
                    ud_mnemonic_code.UD_Iles => "ES",
                    ud_mnemonic_code.UD_Ilfs => "FS",
                    ud_mnemonic_code.UD_Ilgs => "GS",
                    ud_mnemonic_code.UD_Ilss => "SS",
                    _ => "?"
                };
                
                // Try to find the register being loaded
                var modrm = b[b.Length > 2 && (b[0] == 0x0F || b[0] == 0x2E || b[0] == 0x3E) ? 2 : 1];
                var reg = (modrm >> 3) & 0x07;
                var regName = GetRegName16(reg);
                return $"LOAD FAR PTR {sreg}:{regName}";
            }

            // REP string operations
            if (text.Contains("rep") || text.Contains("repne"))
            {
                var count = cx.HasValue ? $"0x{cx.Value:X4}" : "CX";
                if (ins.Mnemonic == ud_mnemonic_code.UD_Imovsb || ins.Mnemonic == ud_mnemonic_code.UD_Imovsw)
                {
                    var unit = ins.Mnemonic == ud_mnemonic_code.UD_Imovsw ? "words" : "bytes";
                    return $"MEMCPY: {count} {unit} from DS:SI to ES:DI";
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Istosb || ins.Mnemonic == ud_mnemonic_code.UD_Istosw)
                {
                    var val = (ins.Mnemonic == ud_mnemonic_code.UD_Istosw) ? (ax.HasValue ? $"0x{ax.Value:X4}" : "AX") : (al.HasValue ? $"0x{al.Value:X2}" : "AL");
                    return $"MEMSET: fill {count} with {val} at ES:DI";
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Icmpsb || ins.Mnemonic == ud_mnemonic_code.UD_Icmpsw)
                    return $"MEMCMP: compare {count} units at DS:SI and ES:DI";
                if (ins.Mnemonic == ud_mnemonic_code.UD_Iscasb || ins.Mnemonic == ud_mnemonic_code.UD_Iscasw)
                {
                    var val = (ins.Mnemonic == ud_mnemonic_code.UD_Iscasw) ? (ax.HasValue ? $"0x{ax.Value:X4}" : "AX") : (al.HasValue ? $"0x{al.Value:X2}" : "AL");
                    return $"MEMSCAN: find {val} in {count} units at ES:DI";
                }
            }

            // DOS INT 21h Sub-functions
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iint && b.Length >= 2 && b[0] == 0xCD && b[1] == 0x21)
            {
                if (ah == 0x25) {
                    var alHex = al.HasValue ? $"{al.Value:X2}h" : "AL";
                    return $"DOS: Set INT {alHex} vector (hook) to DS:DX";
                }
                if (ah == 0x35) {
                    var alHex = al.HasValue ? $"{al.Value:X2}h" : "AL";
                    return $"DOS: Get INT {alHex} vector (returns ES:BX)";
                }
                if (ah == 0x48) {
                    var bxStr = bx.HasValue ? $"{bx.Value} paragraphs (0x{bx.Value:X4})" : "BX paragraphs";
                    return $"DOS: Allocate Memory ({bxStr})";
                }
                if (ah == 0x49) {
                    var esStr = es.HasValue ? $"0x{es.Value:X4}" : "ES";
                    return $"DOS: Free Memory at 0x{esStr}";
                }
                if (ah == 0x3D) {
                    var access = (al.HasValue) ? (al.Value & 0x03) switch { 0 => "Read", 1 => "Write", 2 => "R/W", _ => "?" } : "AL";
                    return $"DOS: Open File (Access: {access}) DS:DX -> filename";
                }
                if (ah == 0x3E) return $"DOS: Close File (Handle: BX)";
                if (ah == 0x3F) return $"DOS: Read File (Handle: BX, CX bytes to DS:DX)";
                if (ah == 0x40) return $"DOS: Write File (Handle: BX, CX bytes from DS:DX)";
            }

            // BIOS INT 10h (Video) Sub-functions
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iint && b.Length >= 2 && b[0] == 0xCD && b[1] == 0x10)
            {
                if (ah == 0x02) {
                    var dhStr = dx.HasValue ? $"R:{(dx.Value >> 8)}" : "DH";
                    var dlStr = dx.HasValue ? $"C:{(dx.Value & 0xFF)}" : "DL";
                    var bhStr = bx.HasValue ? $"Pg:{(bx.Value >> 8)}" : "BH";
                    return $"BIOS Video: Set Cursor {dhStr},{dlStr} {bhStr}";
                }
                if (ah == 0x09) {
                    var alStr = ax.HasValue ? $"Char:{(char)(ax.Value & 0xFF)}" : "AL";
                    var blStr = bx.HasValue ? $"Attr:0x{(bx.Value & 0xFF):X2}" : "BL";
                    var cxStr = cx.HasValue ? $"Count:{cx.Value}" : "CX";
                    return $"BIOS Video: Write Char/Attr {alStr} {blStr} {cxStr}";
                }
            }

            // Shift-by-CL (helps make bit-twiddling less opaque)
            if (b[0] == 0xD3 && b.Length >= 2 && cx.HasValue)
            {
                var cl = (byte)(cx.Value & 0xFF);
                var modrm = b[1];
                var mod = (modrm >> 6) & 0x03;
                var reg = (modrm >> 3) & 0x07;
                var rm = modrm & 0x07;
                if (mod == 0x03) // register operand
                {
                    var regName = GetRegName16(rm);

                    if (!string.IsNullOrEmpty(regName) && (reg == 4 || reg == 5 || reg == 7))
                    {
                        var op = reg switch
                        {
                            4 => "<<=",
                            5 => ">>=",
                            7 => ">>= (arith)",
                            _ => "?"
                        };
                        var mult = cl == 4 && reg == 4 ? " (x16)" : string.Empty;
                        var div = cl == 4 && (reg == 5 || reg == 7) ? " (/16)" : string.Empty;
                        return $"SHIFT: {regName} {op} {cl}{mult}{div}";
                    }
                }
            }

            // Detect writing a FAR pointer at [disp] via consecutive stores to [disp] and [disp+2]
            if (b.Length >= 4 && b[0] == 0x89)
            {
                var modrm = b[1];
                var mod = (modrm >> 6) & 0x03;
                var reg = (modrm >> 3) & 0x07;
                var rm = modrm & 0x07;
                if (mod == 0x00 && rm == 0x06)
                {
                    var disp = (ushort)(b[2] | (b[3] << 8));

                    // current: mov [disp], reg (segment part)
                    if (prev?.Bytes != null && prev.Bytes.Length >= 4)
                    {
                        var pb = prev.Bytes;
                        if (pb[0] == 0x89)
                        {
                            var pmodrm = pb[1];
                            var pmod = (pmodrm >> 6) & 0x03;
                            var preg = (pmodrm >> 3) & 0x07;
                            var prm = pmodrm & 0x07;
                            if (pmod == 0x00 && prm == 0x06)
                            {
                                var pdisp = (ushort)(pb[2] | (pb[3] << 8));
                                // We check for consecutive writes to [X] and [X+2] where X is 4-byte aligned (possible IVT vector)
                                if (disp == pdisp + 2 && (pdisp % 4) == 0)
                                {
                                    string pVal = GetRegName16(preg);
                                    string vVal = GetRegName16(reg);
                                    int intNo = pdisp / 4;

                                    if (ds.HasValue && ds.Value == 0x0000)
                                        return $"WRITE IVT INT {intNo:X2}h vector = {vVal}:{pVal}";
                                    if (ds.HasValue && ds.Value < 0x0100) // Also likely IVT if DS is very low
                                        return $"WRITE IVT? INT {intNo:X2}h vector = {vVal}:{pVal} (DS=0x{ds.Value:X4})";
                                    
                                    if (ds.HasValue)
                                        return $"STORE FAR PTR [DS:{pdisp:X4}] = {vVal}:{pVal} (DS=0x{ds.Value:X4})";
                                    
                                    return $"STORE FAR PTR [DS:{pdisp:X4}] = {vVal}:{pVal}";
                                }
                                // Generic consecutive FAR-ptr-like store
                                if (disp == pdisp + 2)
                                {
                                    string pVal = GetRegName16(preg);
                                    string vVal = GetRegName16(reg);
                                    if (ds.HasValue && ds.Value == 0x0000)
                                    {
                                        var maybeIntNo = pdisp / 4;
                                        return $"STORE FAR PTR [DS:{pdisp:X4}] = {vVal}:{pVal} (IVT? INT {maybeIntNo:X2}h)";
                                    }
                                    return $"STORE FAR PTR [DS:{pdisp:X4}] = {vVal}:{pVal}";
                                }
                            }
                        }
                    }
                }
            }

            // Stack switch: mov sp, reg after mov ss, reg
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && text.Contains("sp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Imov && prev.ToString().Contains("ss"))
            {
                if (Regex.IsMatch(text, @"\bsp\b") && Regex.IsMatch(prev.ToString(), @"\bss\b"))
                {
                    return "SETUP STACK";
                }
            }

            // Segment setup

            var bdaHint = TryGetBiosDataAreaHint(text, ds, es);
            if (!string.IsNullOrEmpty(bdaHint))
                return bdaHint;

            var pspHint = TryGetPspHint(text, ds, es, index);
            if (!string.IsNullOrEmpty(pspHint))
                return pspHint;
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && ax.HasValue && text.Contains("ax"))
            {
                if (Regex.IsMatch(text, @"\bds\b,\s*ax\b")) return $"SET DS=0x{ax.Value:X4}";
                if (Regex.IsMatch(text, @"\bes\b,\s*ax\b")) return $"SET ES=0x{ax.Value:X4}";
                if (Regex.IsMatch(text, @"\bss\b,\s*ax\b")) return $"SET SS=0x{ax.Value:X4}";
            }

            // Direction flag
            if (ins.Mnemonic == ud_mnemonic_code.UD_Icld) return "Direction: Forward";
            if (ins.Mnemonic == ud_mnemonic_code.UD_Istd) return "Direction: Backward";

            // ES = DS
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop && text.Contains("es") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Ipush && prev.ToString().Contains("ds"))
            {
                if (Regex.IsMatch(text, @"\bes\b") && Regex.IsMatch(prev.ToString(), @"\bds\b"))
                    return "ES = DS";
            }

            // REP STOSB: memset
            if (b[0] == 0xF3 && b.Length >= 2 && b[1] == 0xAA)
            {
                string detail = "memset";
                if (es.HasValue && di.HasValue) detail += $"(ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $"(DI=0x{di.Value:X4}";
                else detail += "(";

                if (al.HasValue) detail += $", val=0x{al.Value:X2}";
                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";
                
                return detail;
            }

            // REP STOSW: memset (word)
            if (b[0] == 0xF3 && b.Length >= 2 && b[1] == 0xAB)
            {
                string detail = "memsetw";
                if (es.HasValue && di.HasValue) detail += $"(ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $"(DI=0x{di.Value:X4}";
                else detail += "(";

                if (ax.HasValue) detail += $", val=0x{ax.Value:X4}";
                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";

                return detail;
            }

            // REP MOVSB/W: memcpy
            if (b[0] == 0xF3 && b.Length >= 2 && (b[1] == 0xA4 || b[1] == 0xA5))
            {
                bool isWord = b[1] == 0xA5;
                string detail = isWord ? "memmovew" : "memmoveb";
                if (ds.HasValue && si.HasValue) detail += $"(from DS:0x{si.Value:X4} [seg=0x{ds.Value:X4}]";
                else if (si.HasValue) detail += $"(from SI=0x{si.Value:X4}";
                else detail += "(from ?";

                if (es.HasValue && di.HasValue) detail += $", to ES:0x{di.Value:X4} [seg=0x{es.Value:X4}]";
                else if (di.HasValue) detail += $", to DI=0x{di.Value:X4}";
                else detail += ", to ?";

                if (cx.HasValue) detail += $", count=0x{cx.Value:X4})";
                else detail += ")";

                return detail;
            }

            // REPNE SCASB: strlen
            if (b[0] == 0xF2 && b.Length >= 2 && b[1] == 0xAE)
            {
                return "strlen (find AL in ES:DI)";
            }

            // REPE CMPSB/W: memcmp
            if (b[0] == 0xF3 && b.Length >= 2 && (b[1] == 0xA6 || b[1] == 0xA7))
            {
                return $"memcmp { (b[1] == 0xA7 ? "word" : "byte") } (DS:SI vs ES:DI)";
            }

            // Far CALL to segment:offset
            if (b[0] == 0x9A && b.Length >= 5)
            {
                ushort off = (ushort)(b[1] | (b[2] << 8));
                ushort seg = (ushort)(b[3] | (b[4] << 8));
                return $"CALL FAR {seg:X4}:{off:X4}";
            }

            // Far JMP to segment:offset
            if (b[0] == 0xEA && b.Length >= 5)
            {
                ushort off = (ushort)(b[1] | (b[2] << 8));
                ushort seg = (ushort)(b[3] | (b[4] << 8));
                return $"JMP FAR {seg:X4}:{off:X4}";
            }

            // Function markers
            if (ins.Mnemonic == ud_mnemonic_code.UD_Imov && text.Contains("bp, sp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Ipush && prev.ToString().Contains("bp"))
            {
                return "FUNC PROLOGUE";
            }
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop && text.Contains("bp") && prev != null && prev.Mnemonic == ud_mnemonic_code.UD_Imov && prev.ToString().Contains("sp, bp"))
            {
                return "FUNC EPILOGUE (LEAVE)";
            }

            // Segment pointer loads
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ilds) return "LDS: load DS:reg with far pointer";
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iles) return "LES: load ES:reg with far pointer";

            // INT 3: Debug break
            if (b[0] == 0xCC) return "DEBUG BREAK";

            return null;
        }

        private static string TryGetBiosDataAreaHint(string insText, ushort? ds, ushort? es)
        {
            if (string.IsNullOrEmpty(insText))
                return null;

            // BDA lives at segment 0040h
            var bdaSeg = (ushort)0x0040;
            if (ds != bdaSeg && es != bdaSeg)
                return null;

            // Match direct memory operands like: [0x6c], [es:0x6c], [ds:0x10]
            var m = Regex.Match(insText, @"\[(?:(?<seg>cs|ds|es|ss):)?0x(?<hex>[0-9a-fA-F]+)\]");
            if (!m.Success)
                return null;

            var seg = m.Groups["seg"].Success ? m.Groups["seg"].Value : null;
            if (!int.TryParse(m.Groups["hex"].Value, System.Globalization.NumberStyles.HexNumber, null, out var off))
                return null;

            ushort? effectiveSeg = seg switch
            {
                "ds" => ds,
                "es" => es,
                _ => ds // default for [disp16] is DS
            };

            if (effectiveSeg != bdaSeg)
                return null;

            // A small curated list of the most common BDA fields.
            // Offsets are within the 0040:0000 area.
            var desc = off switch
            {
                0x0000 => "COM1 base I/O port (word)",
                0x0002 => "COM2 base I/O port (word)",
                0x0004 => "COM3 base I/O port (word)",
                0x0006 => "COM4 base I/O port (word)",
                0x0008 => "LPT1 base I/O port (word)",
                0x000A => "LPT2 base I/O port (word)",
                0x000C => "LPT3 base I/O port (word)",
                0x0010 => "Equipment list",
                0x0013 => "Conventional memory size (KB)",
                0x0017 => "Keyboard shift flags",
                0x0040 => "Floppy drive motor/status",
                0x0049 => "Current video mode",
                0x0060 => "Keyboard buffer head",
                0x0062 => "Keyboard buffer tail",
                0x006C => "BIOS tick count (dword, ~18.2Hz since midnight)",
                _ => null
            };

            if (string.IsNullOrEmpty(desc))
                return null;

            return $"BDA 0040:{off:X4}h ; {desc}";
        }

        private static string TryGetPspHint(string insText, ushort? ds, ushort? es, int index)
        {
            if (string.IsNullOrEmpty(insText))
                return null;

            // PSP is in DS/ES at program startup, but we usually don't know the segment value.
            // Keep this very conservative: only near the entry function and only for well-known PSP offsets.
            if (index > 200)
                return null;

            // If DS/ES is explicitly set to the BDA, don't label as PSP.
            if (ds == 0x0040 || es == 0x0040)
                return null;

            var m = Regex.Match(insText, @"\[(?:(?<seg>cs|ds|es|ss):)?0x(?<hex>[0-9a-fA-F]+)\]");
            if (!m.Success)
                return null;

            if (!int.TryParse(m.Groups["hex"].Value, System.Globalization.NumberStyles.HexNumber, null, out var off))
                return null;

            // Only very low offsets are plausible PSP references.
            if (off > 0x00FF)
                return null;

            var desc = off switch
            {
                0x0000 => "INT 20h instruction / CP/M entrypoint",
                0x0002 => "Memory size (paragraphs)",
                0x0005 => "DOS function dispatcher entry (far call)",
                0x000A => "Terminate address (INT 22h) vector",
                0x000C => "Ctrl-Break address (INT 23h) vector",
                0x000E => "Critical error handler (INT 24h) vector",
                0x0016 => "Parent PSP segment",
                0x002C => "Environment segment (word)",
                0x005C => "FCB #1 (default)",
                0x006C => "FCB #2 (default)",
                0x0080 => "Command tail length",
                0x0081 => "Command tail buffer",
                _ => null
            };

            if (string.IsNullOrEmpty(desc))
                return null;

            return $"PSP? +{off:X2}h ; {desc}";
        }

        private static string TryDecodeExecParamBlockFromStack(sbyte? bxBpDisp8, bool esIsSs, Dictionary<sbyte, ushort> bpFrameWords, Dictionary<sbyte, string> bpFrameSyms, byte[] module)
        {
            if (!bxBpDisp8.HasValue || !esIsSs || bpFrameWords == null)
                return string.Empty;

            var baseDisp = bxBpDisp8.Value;

            static bool TryGetWord(Dictionary<sbyte, ushort> words, sbyte disp, out ushort v)
            {
                if (words != null && words.TryGetValue(disp, out v))
                    return true;
                v = 0;
                return false;
            }

            var haveCmdOff = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 2), out var cmdOff);
            var haveCmdSeg = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 4), out var cmdSeg);
            var haveFcb1Off = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 6), out var fcb1Off);
            var haveFcb1Seg = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 8), out var fcb1Seg);
            var haveFcb2Off = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 10), out var fcb2Off);
            var haveFcb2Seg = TryGetWord(bpFrameWords, (sbyte)(baseDisp + 12), out var fcb2Seg);

            string GetSym(sbyte disp)
            {
                if (bpFrameSyms != null && bpFrameSyms.TryGetValue(disp, out var s) && !string.IsNullOrEmpty(s))
                    return s;
                return null;
            }

            var sb = new StringBuilder();
            sb.Append($"PB(stack @BP{(baseDisp >= 0 ? "+" : "")}{baseDisp})");

            if (haveCmdOff && haveCmdSeg)
            {
                sb.Append($" cmd={cmdSeg:X4}:{cmdOff:X4}");
                var cmdLinear = (uint)((cmdSeg << 4) + cmdOff);
                var cmd = TryReadDosCommandTail(module, cmdLinear, 126);
                if (!string.IsNullOrEmpty(cmd)) sb.Append($" \"{cmd}\"");
            }
            else
            {
                var offSym = GetSym((sbyte)(baseDisp + 2));
                var segSym = GetSym((sbyte)(baseDisp + 4));
                if (!string.IsNullOrEmpty(offSym) || !string.IsNullOrEmpty(segSym))
                    sb.Append($" cmd={(segSym ?? "?")}:{(offSym ?? "?")}");
                else
                    sb.Append(" cmd=[BP+2..BP+4]");
            }

            if (haveFcb1Off && haveFcb1Seg)
            {
                sb.Append($" fcb1={fcb1Seg:X4}:{fcb1Off:X4}");
                var linear = (uint)((fcb1Seg << 4) + fcb1Off);
                var f = TryFormatFcbDetail(linear, module);
                if (!string.IsNullOrEmpty(f)) sb.Append($" {f}");
            }
            else
            {
                var offSym = GetSym((sbyte)(baseDisp + 6));
                var segSym = GetSym((sbyte)(baseDisp + 8));
                if (!string.IsNullOrEmpty(offSym) || !string.IsNullOrEmpty(segSym))
                    sb.Append($" fcb1={(segSym ?? "?")}:{(offSym ?? "?")}");
                else
                    sb.Append(" fcb1=[BP+6..BP+8]");
            }

            if (haveFcb2Off && haveFcb2Seg)
            {
                sb.Append($" fcb2={fcb2Seg:X4}:{fcb2Off:X4}");
                var linear = (uint)((fcb2Seg << 4) + fcb2Off);
                var f = TryFormatFcbDetail(linear, module);
                if (!string.IsNullOrEmpty(f)) sb.Append($" {f}");
            }
            else
            {
                var offSym = GetSym((sbyte)(baseDisp + 10));
                var segSym = GetSym((sbyte)(baseDisp + 12));
                if (!string.IsNullOrEmpty(offSym) || !string.IsNullOrEmpty(segSym))
                    sb.Append($" fcb2={(segSym ?? "?")}:{(offSym ?? "?")}");
                else
                    sb.Append(" fcb2=[BP+10..BP+12]");
            }

            return sb.ToString();
        }

        private static void UpdateSimpleDosState(
            Instruction ins,
            ref byte? lastAh,
            ref byte? lastAl,
            ref ushort? lastAxImm,
            ref ushort? lastBxImm,
            ref ushort? lastCxImm,
            ref ushort? lastDxImm,
            ref ushort? lastSiImm,
            ref ushort? lastDiImm,
            ref ushort? lastBpImm,
            ref ushort? lastDsImm,
            ref ushort? lastEsImm)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return;

            string text = ins.ToString().ToLower();

            // xor reg, reg or sub reg, reg
            if (ins.Mnemonic == ud_mnemonic_code.UD_Ixor || ins.Mnemonic == ud_mnemonic_code.UD_Isub)
            {
                if (text.Contains("ax, ax")) { lastAxImm = 0; lastAh = 0; lastAl = 0; return; }
                if (text.Contains("bx, bx")) { lastBxImm = 0; return; }
                if (text.Contains("cx, cx")) { lastCxImm = 0; return; }
                if (text.Contains("dx, dx")) { lastDxImm = 0; return; }
                if (text.Contains("si, si")) { lastSiImm = 0; return; }
                if (text.Contains("di, di")) { lastDiImm = 0; return; }
            }

            // xor al, al: 30 C0
            if (b.Length >= 2 && b[0] == 0x30 && b[1] == 0xC0)
            {
                lastAl = 0;
                if (lastAh.HasValue) lastAxImm = (ushort)(lastAh.Value << 8);
                else if (lastAxImm.HasValue) lastAxImm = (ushort)(lastAxImm.Value & 0xFF00);
                return;
            }

            // mov ah, imm8: B4 ib
            if (b[0] == 0xB4 && b.Length >= 2)
            {
                lastAh = b[1];
                if (lastAl.HasValue) lastAxImm = (ushort)((lastAh.Value << 8) | lastAl.Value);
                else lastAxImm = null;
                return;
            }

            // mov al, imm8: B0 ib
            if (b[0] == 0xB0 && b.Length >= 2)
            {
                lastAl = b[1];
                if (lastAh.HasValue) lastAxImm = (ushort)((lastAh.Value << 8) | lastAl.Value);
                else if (lastAxImm.HasValue) lastAxImm = (ushort)((lastAxImm.Value & 0xFF00) | lastAl.Value);
                return;
            }

            // mov ax, imm16: B8 iw
            if (b[0] == 0xB8 && b.Length >= 3)
            {
                lastAxImm = (ushort)(b[1] | (b[2] << 8));
                lastAh = (byte)(lastAxImm >> 8);
                lastAl = (byte)(lastAxImm & 0xFF);
                return;
            }

            // mov bx, imm16: BB iw
            if (b[0] == 0xBB && b.Length >= 3)
            {
                lastBxImm = (ushort)(b[1] | (b[2] << 8));
                return;
            }

            // mov cl, imm8: B1 ib etc
            if (b[0] == 0xB3 && b.Length >= 2) { lastBxImm = lastBxImm.HasValue ? (ushort)((lastBxImm.Value & 0xFF00) | b[1]) : (ushort)b[1]; return; }
            if (b[0] == 0xB1 && b.Length >= 2) { lastCxImm = lastCxImm.HasValue ? (ushort)((lastCxImm.Value & 0xFF00) | b[1]) : (ushort)b[1]; return; }
            if (b[0] == 0xB2 && b.Length >= 2) { lastDxImm = lastDxImm.HasValue ? (ushort)((lastDxImm.Value & 0xFF00) | b[1]) : (ushort)b[1]; return; }
            if (b[0] == 0xB7 && b.Length >= 2) { lastBxImm = lastBxImm.HasValue ? (ushort)((lastBxImm.Value & 0x00FF) | (b[1] << 8)) : (ushort)(b[1] << 8); return; }
            if (b[0] == 0xB5 && b.Length >= 2) { lastCxImm = lastCxImm.HasValue ? (ushort)((lastCxImm.Value & 0x00FF) | (b[1] << 8)) : (ushort)(b[1] << 8); return; }
            if (b[0] == 0xB6 && b.Length >= 2) { lastDxImm = lastDxImm.HasValue ? (ushort)((lastDxImm.Value & 0x00FF) | (b[1] << 8)) : (ushort)(b[1] << 8); return; }

            // mov cx, imm16: B9 iw
            if (b[0] == 0xB9 && b.Length >= 3) { lastCxImm = (ushort)(b[1] | (b[2] << 8)); return; }
            if (b[0] == 0xBA && b.Length >= 3) { lastDxImm = (ushort)(b[1] | (b[2] << 8)); return; }
            if (b[0] == 0xBE && b.Length >= 3) { lastSiImm = (ushort)(b[1] | (b[2] << 8)); return; }
            if (b[0] == 0xBF && b.Length >= 3) { lastDiImm = (ushort)(b[1] | (b[2] << 8)); return; }
            if (b[0] == 0xBD && b.Length >= 3) { lastBpImm = (ushort)(b[1] | (b[2] << 8)); return; }

            // Register moves
            if (b.Length >= 2 && b[0] == 0x89)
            {
                if (b[1] == 0xC3) { lastBxImm = lastAxImm; return; }
                if (b[1] == 0xC1) { lastCxImm = lastAxImm; return; }
                if (b[1] == 0xC2) { lastDxImm = lastAxImm; return; }
                if (b[1] == 0xC6) { lastSiImm = lastAxImm; return; }
                if (b[1] == 0xC7) { lastDiImm = lastAxImm; return; }
                if (b[1] == 0xC5) { lastBpImm = lastAxImm; return; }
                if (b[1] == 0xD8) { lastAxImm = lastBxImm; return; }
                if (b[1] == 0xD1) { lastCxImm = lastBxImm; return; }
                if (b[1] == 0xD2) { lastDxImm = lastBxImm; return; }
                if (b[1] == 0xDD) { lastBpImm = lastBxImm; return; }
                if (b[1] == 0xE0) { lastAxImm = lastCxImm; return; }
                if (b[1] == 0xEB) { lastBxImm = lastCxImm; return; }
                if (b[1] == 0xEA) { lastDxImm = lastCxImm; return; }
                if (b[1] == 0xCD) { lastBpImm = lastCxImm; return; }
                if (b[1] == 0xF0) { lastAxImm = lastDxImm; return; }
                if (b[1] == 0xFB) { lastBxImm = lastDxImm; return; }
                if (b[1] == 0xF9) { lastCxImm = lastDxImm; return; }
                if (b[1] == 0xD5) { lastBpImm = lastDxImm; return; }
            }

            if (b.Length >= 2 && b[0] == 0x8E)
            {
                if (b[1] == 0xD8) { lastDsImm = lastAxImm; return; }
                if (b[1] == 0xDA) { lastDsImm = lastDxImm; return; }
                if (b[1] == 0xDB) { lastDsImm = lastBxImm; return; }
                if (b[1] == 0xD9) { lastDsImm = lastCxImm; return; }
                if (b[1] == 0xC0) { lastEsImm = lastAxImm; return; }
                if (b[1] == 0xC2) { lastEsImm = lastDxImm; return; }
                if (b[1] == 0xC3) { lastEsImm = lastBxImm; return; }
                if (b[1] == 0xC1) { lastEsImm = lastCxImm; return; }
            }

            if (b.Length >= 2 && b[0] == 0x8B)
            {
                if (b[1] == 0xD8) { lastBxImm = lastAxImm; return; }
                if (b[1] == 0xC8) { lastCxImm = lastAxImm; return; }
                if (b[1] == 0xD0) { lastDxImm = lastAxImm; return; }
                if (b[1] == 0xC3) { lastAxImm = lastBxImm; lastAh = (byte?)(lastAxImm >> 8); lastAl = (byte?)(lastAxImm & 0xFF); return; }
                if (b[1] == 0xE8) { lastBpImm = lastAxImm; return; }
            }

            // Arithmetic
            if (ins.Mnemonic == ud_mnemonic_code.UD_Iinc)
            {
                if (text.Contains("ax") && lastAxImm.HasValue) { lastAxImm++; lastAh = (byte?)(lastAxImm >> 8); lastAl = (byte?)(lastAxImm & 0xFF); return; }
                if (text.Contains("bx") && lastBxImm.HasValue) { lastBxImm++; return; }
                if (text.Contains("cx") && lastCxImm.HasValue) { lastCxImm++; return; }
                if (text.Contains("dx") && lastDxImm.HasValue) { lastDxImm++; return; }
            }
            if (ins.Mnemonic == ud_mnemonic_code.UD_Idec)
            {
                if (text.Contains("ax") && lastAxImm.HasValue) { lastAxImm--; lastAh = (byte?)(lastAxImm >> 8); lastAl = (byte?)(lastAxImm & 0xFF); return; }
                if (text.Contains("bx") && lastBxImm.HasValue) { lastBxImm--; return; }
                if (text.Contains("cx") && lastCxImm.HasValue) { lastCxImm--; return; }
                if (text.Contains("dx") && lastDxImm.HasValue) { lastDxImm--; return; }
            }

            // Clobbers
            var firstComma = text.IndexOf(',');
            var dest = firstComma != -1 ? text.Substring(0, firstComma) : text;

            if (dest.Contains("ax")) { lastAxImm = null; lastAh = null; lastAl = null; }
            else if (dest.Contains("ah")) { lastAh = null; lastAxImm = null; }
            else if (dest.Contains("al")) { lastAl = null; lastAxImm = null; }
            else if (dest.Contains("bx")) lastBxImm = null;
            else if (dest.Contains("bl")) { if (lastBxImm.HasValue) lastBxImm = (ushort)(lastBxImm.Value & 0xFF00); else lastBxImm = null; }
            else if (dest.Contains("bh")) { if (lastBxImm.HasValue) lastBxImm = (ushort)(lastBxImm.Value & 0x00FF); else lastBxImm = null; }
            else if (dest.Contains("cx")) lastCxImm = null;
            else if (dest.Contains("cl")) { if (lastCxImm.HasValue) lastCxImm = (ushort)(lastCxImm.Value & 0xFF00); else lastCxImm = null; }
            else if (dest.Contains("ch")) { if (lastCxImm.HasValue) lastCxImm = (ushort)(lastCxImm.Value & 0x00FF); else lastCxImm = null; }
            else if (dest.Contains("dx")) lastDxImm = null;
            else if (dest.Contains("dl")) { if (lastDxImm.HasValue) lastDxImm = (ushort)(lastDxImm.Value & 0xFF00); else lastDxImm = null; }
            else if (dest.Contains("dh")) { if (lastDxImm.HasValue) lastDxImm = (ushort)(lastDxImm.Value & 0x00FF); else lastDxImm = null; }
            else if (dest.Contains("si")) lastSiImm = null;
            else if (dest.Contains("di")) lastDiImm = null;
            else if (dest.Contains("bp")) lastBpImm = null;
            else if (dest.Contains("ds")) lastDsImm = null;
            else if (dest.Contains("es")) lastEsImm = null;

            if (ins.Mnemonic == ud_mnemonic_code.UD_Ipop || ins.Mnemonic == ud_mnemonic_code.UD_Icall || 
                ins.Mnemonic == ud_mnemonic_code.UD_Imul || ins.Mnemonic == ud_mnemonic_code.UD_Idiv ||
                ins.Mnemonic == ud_mnemonic_code.UD_Iloop || ins.Mnemonic == ud_mnemonic_code.UD_Iloope || ins.Mnemonic == ud_mnemonic_code.UD_Iloopne ||
                ins.Mnemonic == ud_mnemonic_code.UD_Imovsb || ins.Mnemonic == ud_mnemonic_code.UD_Imovsw || ins.Mnemonic == ud_mnemonic_code.UD_Istosb || ins.Mnemonic == ud_mnemonic_code.UD_Istosw ||
                ins.Mnemonic == ud_mnemonic_code.UD_Icmpsb || ins.Mnemonic == ud_mnemonic_code.UD_Icmpsw || ins.Mnemonic == ud_mnemonic_code.UD_Iscasb || ins.Mnemonic == ud_mnemonic_code.UD_Iscasw)
            {
                if (ins.Mnemonic == ud_mnemonic_code.UD_Icall || ins.Mnemonic == ud_mnemonic_code.UD_Imul || ins.Mnemonic == ud_mnemonic_code.UD_Idiv)
                {
                    lastAxImm = null; lastAh = null; lastAl = null;
                    lastDxImm = null; 
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Iloop || ins.Mnemonic == ud_mnemonic_code.UD_Iloope || ins.Mnemonic == ud_mnemonic_code.UD_Iloopne)
                {
                    lastCxImm = null;
                }
                if (ins.Mnemonic == ud_mnemonic_code.UD_Imovsb || ins.Mnemonic == ud_mnemonic_code.UD_Imovsw || ins.Mnemonic == ud_mnemonic_code.UD_Istosb || ins.Mnemonic == ud_mnemonic_code.UD_Istosw ||
                    ins.Mnemonic == ud_mnemonic_code.UD_Icmpsb || ins.Mnemonic == ud_mnemonic_code.UD_Icmpsw || ins.Mnemonic == ud_mnemonic_code.UD_Iscasb || ins.Mnemonic == ud_mnemonic_code.UD_Iscasw)
                {
                    lastSiImm = null; lastDiImm = null;
                    if (text.Contains("rep")) lastCxImm = 0;
                }
            }
        }

        private static string GetRegName16(int reg)
        {
            return reg switch
            {
                0 => "AX",
                1 => "CX",
                2 => "DX",
                3 => "BX",
                4 => "SP",
                5 => "BP",
                6 => "SI",
                7 => "DI",
                _ => $"R{reg}"
            };
        }
    }
}
