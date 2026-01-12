using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private sealed class IoPortStats
        {
            public int Reads;
            public int Writes;
        }

        private static readonly Dictionary<ushort, string> KnownIoPorts = new Dictionary<ushort, string>
        {
            // VGA / EGA ports (common in DOS games and demos)
            [0x03C0] = "VGA Attribute Controller",
            [0x03C1] = "VGA Attribute Data",
            [0x03C2] = "VGA Misc Output",
            [0x03C4] = "VGA Sequencer Index",
            [0x03C5] = "VGA Sequencer Data",
            [0x03C7] = "VGA DAC state/address",
            [0x03C8] = "VGA DAC index",
            [0x03C9] = "VGA DAC data",
            [0x03CC] = "VGA Misc Output (read)",
            [0x03CE] = "VGA Graphics Ctrl Index",
            [0x03CF] = "VGA Graphics Ctrl Data",
            [0x03D4] = "VGA CRTC Index",
            [0x03D5] = "VGA CRTC Data",
            [0x03DA] = "VGA Input Status 1",

            // PIC / PIT (IRQ/timers)
            [0x0020] = "PIC1 Command",
            [0x0021] = "PIC1 Data",
            [0x00A0] = "PIC2 Command",
            [0x00A1] = "PIC2 Data",
            [0x0040] = "PIT Channel 0 Data",
            [0x0041] = "PIT Channel 1 Data",
            [0x0042] = "PIT Channel 2 Data",
            [0x0043] = "PIT Mode/Command",

            // Sound / Game ports
            [0x0201] = "Game Port",
            [0x0388] = "AdLib FM Synthesis",
            [0x0220] = "SoundBlaster Base (220h)",
            [0x0224] = "SoundBlaster Mixer Board Index",
            [0x0225] = "SoundBlaster Mixer Board Data",
            [0x0226] = "SoundBlaster DSP Reset",
            [0x022A] = "SoundBlaster DSP Read Data",
            [0x022C] = "SoundBlaster DSP Write Data/Command",
            [0x022E] = "SoundBlaster DSP Read Buffer Status",
            [0x0330] = "MPU-401 (MIDI)",
        };

        private static bool TryParseMovDxImmediate(string insText, out ushort dxImm)
        {
            dxImm = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Typical output: "mov dx, 03C8h" or "mov dx, 0x3c8".
            var m = Regex.Match(insText, @"^\s*mov\s+dx\s*,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var token = m.Groups["imm"].Value;
            if (!TryParseImmUShort(token, out dxImm))
                return false;
            return true;
        }

        private static bool TryParseImmUShort(string token, out ushort value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(token))
                return false;

            token = token.Trim();

            // Prefer hex when it looks like hex.
            var isHex = token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || token.Any(c => (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                token = token.Substring(2);

            if (isHex)
            {
                if (!uint.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out var hex))
                    return false;
                if (hex > 0xFFFF)
                    return false;
                value = (ushort)hex;
                return true;
            }

            if (!uint.TryParse(token, out var dec))
                return false;
            if (dec > 0xFFFF)
                return false;
            value = (ushort)dec;
            return true;
        }

        private static bool TryParseIoAccess(string insText, ushort? lastDxImm16, out ushort port, out bool isWrite, out string dataReg)
        {
            port = 0;
            isWrite = false;
            dataReg = null;

            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // out dx, al|ax|eax  OR out imm, al|ax|eax
            var mout = Regex.Match(insText, @"^\s*out\s+(?<port>dx|(?:0x)?[0-9A-Fa-f]+h?)\s*,\s*(?<reg>al|ax|eax)\s*$", RegexOptions.IgnoreCase);
            if (mout.Success)
            {
                isWrite = true;
                dataReg = mout.Groups["reg"].Value.ToLowerInvariant();

                var p = mout.Groups["port"].Value.Trim();
                if (p.Equals("dx", StringComparison.OrdinalIgnoreCase))
                {
                    if (!lastDxImm16.HasValue)
                        return false;
                    port = lastDxImm16.Value;
                    return true;
                }

                p = p.TrimEnd('h', 'H');
                return TryParseImmUShort(p, out port);
            }

            // in al|ax|eax, dx  OR in al|ax|eax, imm
            var min = Regex.Match(insText, @"^\s*in\s+(?<reg>al|ax|eax)\s*,\s*(?<port>dx|(?:0x)?[0-9A-Fa-f]+h?)\s*$", RegexOptions.IgnoreCase);
            if (min.Success)
            {
                isWrite = false;
                dataReg = min.Groups["reg"].Value.ToLowerInvariant();

                var p = min.Groups["port"].Value.Trim();
                if (p.Equals("dx", StringComparison.OrdinalIgnoreCase))
                {
                    if (!lastDxImm16.HasValue)
                        return false;
                    port = lastDxImm16.Value;
                    return true;
                }

                p = p.TrimEnd('h', 'H');
                return TryParseImmUShort(p, out port);
            }

            return false;
        }

        private static bool TryParseMovAlImmediate(string insText, out byte imm8)
        {
            imm8 = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var m = Regex.Match(insText.Trim(), @"^mov\s+al,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var tok = m.Groups["imm"].Value.Trim();
            if (!TryParseHexOrDecUInt32(tok, out var u) || u > 0xFF)
                return false;

            imm8 = (byte)u;
            return true;
        }

        private static bool TryParseMovAxImmediate(string insText, out ushort imm16)
        {
            imm16 = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var m = Regex.Match(insText.Trim(), @"^mov\s+ax,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var tok = m.Groups["imm"].Value.Trim();
            return TryParseImmUShort(tok, out imm16);
        }

        private static bool TryParseXorRegReg(string insText, string reg, out bool isSelfXor)
        {
            isSelfXor = false;
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            var r = Regex.Escape(reg);
            var m = Regex.Match(insText.Trim(), $@"^xor\s+{r}\s*,\s*{r}\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            isSelfXor = true;
            return true;
        }

        private static bool TryParseMovDxFromMemory(string insText, out string mem)
        {
            mem = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var m = Regex.Match(insText.Trim(), @"^mov\s+dx,\s*(?:word\s+)?\[(?<mem>[^\]]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            mem = m.Groups["mem"].Value.Trim();
            return !string.IsNullOrWhiteSpace(mem);
        }

        private static void UpdateIoTrackingFromInstruction(
            string insText,
            ref ushort? lastDxImm16,
            ref string lastDxSource,
            ref byte? lastAlImm8,
            ref ushort? lastAxImm16)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return;

            // Track DX (port register)
            if (TryParseMovDxImmediate(insText, out var dxImm))
            {
                lastDxImm16 = dxImm;
                lastDxSource = $"0x{dxImm:X4}";
                return;
            }

            if (TryParseMovDxFromMemory(insText, out var mem))
            {
                lastDxImm16 = null;
                lastDxSource = $"[{mem}]";
                return;
            }

            // Track AL/AX immediates (common right before OUT)
            if (TryParseMovAlImmediate(insText, out var alImm))
            {
                lastAlImm8 = alImm;
                return;
            }

            if (TryParseMovAxImmediate(insText, out var axImm))
            {
                lastAxImm16 = axImm;
                return;
            }

            if (TryParseXorRegReg(insText, "al", out var selfXorAl) && selfXorAl)
            {
                lastAlImm8 = 0;
                return;
            }

            if (TryParseXorRegReg(insText, "ax", out var selfXorAx) && selfXorAx)
            {
                lastAxImm16 = 0;
                return;
            }
        }

        private static string TryAnnotateIoPortAccess(string insText, ushort? lastDxImm16, string lastDxSource, byte? lastAlImm8, ushort? lastAxImm16)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return string.Empty;

            // Call sites sometimes pass an instruction line that already has other comments appended.
            // Normalize to just the instruction text so our exact-match patterns still work.
            SplitInstructionAndComments(insText, out var instructionOnly, out _);
            insText = instructionOnly;

            // Loose parse so we can still annotate dx-based I/O even when DX isn't an immediate.
            var mout = Regex.Match(insText.Trim(), @"^out\s+(?<port>dx|(?:0x)?[0-9A-Fa-f]+h?)\s*,\s*(?<reg>al|ax|eax)\s*$", RegexOptions.IgnoreCase);
            var min = Regex.Match(insText.Trim(), @"^in\s+(?<reg>al|ax|eax)\s*,\s*(?<port>dx|(?:0x)?[0-9A-Fa-f]+h?)\s*$", RegexOptions.IgnoreCase);
            var isWrite = mout.Success;
            var isRead = min.Success;
            if (!isWrite && !isRead)
                return string.Empty;

            var portTok = (isWrite ? mout.Groups["port"].Value : min.Groups["port"].Value).Trim();
            var dataReg = (isWrite ? mout.Groups["reg"].Value : min.Groups["reg"].Value).Trim().ToLowerInvariant();

            string dataText = dataReg;
            if (dataReg == "al" && lastAlImm8.HasValue)
                dataText = $"al=0x{lastAlImm8.Value:X2}";
            else if (dataReg == "ax" && lastAxImm16.HasValue)
                dataText = $"ax=0x{lastAxImm16.Value:X4}";

            if (portTok.Equals("dx", StringComparison.OrdinalIgnoreCase))
            {
                // Best-effort: use immediate DX if we have it, otherwise still emit a useful hint.
                if (lastDxImm16.HasValue)
                {
                    var port = lastDxImm16.Value;
                    KnownIoPorts.TryGetValue(port, out var name);
                    var dir = isWrite ? "<-" : "->";
                    if (!string.IsNullOrEmpty(name))
                        return $"IO: {(isWrite ? "OUT" : "IN")} {name} (0x{port:X4}) {dir} {dataText}";
                    return $"IO: {(isWrite ? "OUT" : "IN")} 0x{port:X4} {dir} {dataText}";
                }

                var dxDesc = !string.IsNullOrWhiteSpace(lastDxSource) ? lastDxSource : "dx";
                var dir2 = isWrite ? "<-" : "->";
                return $"IO: {(isWrite ? "OUT" : "IN")} (port in {dxDesc}) {dir2} {dataText}";
            }

            // Immediate port
            var p = portTok.TrimEnd('h', 'H');
            if (!TryParseImmUShort(p, out var portImm))
                return string.Empty;

            KnownIoPorts.TryGetValue(portImm, out var name2);

            var dir3 = isWrite ? "<-" : "->";
            if (!string.IsNullOrEmpty(name2))
                return $"IO: {(isWrite ? "OUT" : "IN")} {name2} (0x{portImm:X4}) {dir3} {dataText}";

            return $"IO: {(isWrite ? "OUT" : "IN")} 0x{portImm:X4} {dir3} {dataText}";
        }

        private static void CollectIoPortsForFunction(List<Instruction> instructions, int startIdx, int endIdx, out Dictionary<ushort, IoPortStats> ports)
        {
            ports = new Dictionary<ushort, IoPortStats>();
            if (instructions == null || startIdx < 0 || endIdx > instructions.Count || startIdx >= endIdx)
                return;

            ushort? lastDxImm16 = null;

            for (var i = startIdx; i < endIdx; i++)
            {
                var ins = instructions[i];
                if (ins?.Bytes == null || ins.Bytes.Length == 0)
                    continue;

                if (TryDecodeMovDxImm16(ins.Bytes, out var dxImm16))
                    lastDxImm16 = dxImm16;
                else if (TryDecodeMovEdxImm32(ins.Bytes, out var edxImm32))
                    lastDxImm16 = (ushort)(edxImm32 & 0xFFFF);

                if (!TryDecodeIoAccess(ins.Bytes, lastDxImm16, out var port, out var isWrite))
                    continue;

                if (!ports.TryGetValue(port, out var st))
                    ports[port] = st = new IoPortStats();

                if (isWrite)
                    st.Writes++;
                else
                    st.Reads++;
            }
        }

        private static bool TryDecodeMovDxImm16(byte[] bytes, out ushort imm16)
        {
            imm16 = 0;
            if (bytes == null)
                return false;

            // mov dx, imm16 in 32-bit mode is typically: 66 BA iw
            if (bytes.Length >= 4 && bytes[0] == 0x66 && bytes[1] == 0xBA)
            {
                imm16 = (ushort)(bytes[2] | (bytes[3] << 8));
                return true;
            }

            // mov dx, imm16 in 16-bit mode: BA iw
            if (bytes.Length >= 3 && bytes[0] == 0xBA)
            {
                imm16 = (ushort)(bytes[1] | (bytes[2] << 8));
                return true;
            }

            return false;
        }

        private static bool TryDecodeMovEdxImm32(byte[] bytes, out uint imm32)
        {
            imm32 = 0;
            if (bytes == null)
                return false;

            // mov edx, imm32: BA id
            if (bytes.Length >= 5 && bytes[0] == 0xBA)
            {
                imm32 = (uint)(bytes[1] | (bytes[2] << 8) | (bytes[3] << 16) | (bytes[4] << 24));
                return true;
            }

            return false;
        }

        private static bool TryDecodeIoAccess(byte[] bytes, ushort? lastDxImm16, out ushort port, out bool isWrite)
        {
            port = 0;
            isWrite = false;
            if (bytes == null || bytes.Length == 0)
                return false;

            // Handle operand-size prefix (common for IN/OUT AX,DX and MOV DX,imm16)
            var idx = 0;
            if (bytes.Length >= 2 && bytes[0] == 0x66)
                idx = 1;

            if (idx >= bytes.Length)
                return false;

            var op = bytes[idx];

            // Immediate port forms (8-bit port number)
            // IN AL, imm8:  E4 ib
            // IN AX/EAX,imm8: E5 ib
            // OUT imm8, AL: E6 ib
            // OUT imm8, AX/EAX: E7 ib
            if ((op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) && idx + 1 < bytes.Length)
            {
                port = bytes[idx + 1];
                isWrite = (op == 0xE6 || op == 0xE7);
                return true;
            }

            // DX port forms
            // IN AL, DX:  EC
            // IN AX/EAX,DX: ED
            // OUT DX, AL: EE
            // OUT DX, AX/EAX: EF
            if (op == 0xEC || op == 0xED || op == 0xEE || op == 0xEF)
            {
                if (!lastDxImm16.HasValue)
                    return false;
                port = lastDxImm16.Value;
                isWrite = (op == 0xEE || op == 0xEF);
                return true;
            }

            return false;
        }

        private static string FormatIoPortSummary(Dictionary<ushort, IoPortStats> ports)
        {
            if (ports == null || ports.Count == 0)
                return string.Empty;

            var parts = new List<string>();

            foreach (var kvp in ports.OrderByDescending(k => k.Value.Reads + k.Value.Writes).ThenBy(k => k.Key).Take(8))
            {
                var port = kvp.Key;
                var st = kvp.Value;

                KnownIoPorts.TryGetValue(port, out var name);
                var counts = new List<string>();
                if (st.Reads > 0) counts.Add($"R{st.Reads}");
                if (st.Writes > 0) counts.Add($"W{st.Writes}");
                var countText = counts.Count > 0 ? $" ({string.Join(" ", counts)})" : string.Empty;

                if (!string.IsNullOrEmpty(name))
                    parts.Add($"0x{port:X4} {name}{countText}");
                else
                    parts.Add($"0x{port:X4}{countText}");
            }

            return string.Join(", ", parts);
        }
    }
}
