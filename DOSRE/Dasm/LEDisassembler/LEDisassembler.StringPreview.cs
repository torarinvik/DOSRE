using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string TryInlineStringPreview(string insText,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            List<Instruction> instructions,
            int insIdx,
            Dictionary<uint, string> stringSymbols,
            HashSet<uint> resourceGetterTargets)
        {
            if (string.IsNullOrEmpty(insText) || stringPreview == null || stringPreview.Count == 0)
                return string.Empty;

            // Keep this conservative to avoid spam.
            var lower = insText.TrimStart();
            if (!lower.StartsWith("push ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("lea ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("mov ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Fast path: already has an s_XXXXXXXX token
            var sym = ExtractStringSym(insText);
            if (!string.IsNullOrEmpty(sym) && TryParseStringSym(sym, out var addr) &&
                stringPreview.TryGetValue(addr, out var p0) && !string.IsNullOrEmpty(p0))
            {
                return $"STR: \"{p0}\"";
            }

            // Fast path: r_XXXXXXXX token that also points to a known string preview
            var rsym = ExtractResourceSym(insText);
            if (!string.IsNullOrEmpty(rsym) && TryParseResourceSym(rsym, out var raddr) &&
                TryGetStringPreviewAt(raddr, stringPreview, objects, objBytesByIndex, out var rp0) && !string.IsNullOrEmpty(rp0))
            {
                return $"STR: \"{rp0}\"";
            }

            // Heuristic path: try to resolve a computed/pushed register value to a known string address.
            if (instructions == null || insIdx < 0 || insIdx >= instructions.Count)
                return string.Empty;

            var raw = InsText(instructions[insIdx]);
            if (TryResolveStringFromInstruction(instructions, insIdx, raw, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var p1))
                return $"STR: \"{p1}\"";

            return string.Empty;
        }

        private static bool TryResolveStringSymFromOperand(
            List<Instruction> instructions,
            int callIdx,
            string operandText,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            HashSet<uint> resourceGetterTargets,
            out string sym,
            out string preview)
        {
            sym = string.Empty;
            preview = string.Empty;

            if (stringSymbols == null || stringSymbols.Count == 0 || stringPreview == null || stringPreview.Count == 0)
                return false;

            if (string.IsNullOrWhiteSpace(operandText))
                return false;

            // Direct s_ token
            var direct = ExtractStringSym(operandText);
            if (!string.IsNullOrEmpty(direct) && TryParseStringSym(direct, out var daddr) &&
                TryGetStringPreviewAt(daddr, stringPreview, objects, objBytesByIndex, out var dp) && !string.IsNullOrEmpty(dp))
            {
                sym = direct;
                preview = dp;
                return true;
            }

            // Direct r_ token (resource-derived). If it points to a known string preview, treat it as a string too.
            var rdirect = ExtractResourceSym(operandText);
            if (!string.IsNullOrEmpty(rdirect) && TryParseResourceSym(rdirect, out var rdaddr) &&
                TryGetStringPreviewAt(rdaddr, stringPreview, objects, objBytesByIndex, out var rdp) && !string.IsNullOrEmpty(rdp))
            {
                sym = rdirect;
                preview = rdp;
                return true;
            }

            // Register operand (e.g. push eax)
            var op = operandText.Trim();
            if (IsRegister32(op) && TryResolveRegisterValueBefore(instructions, callIdx, op, out var raddr, resourceGetterTargets))
            {
                if (TryResolveStringAddressFromRaw(raddr, stringSymbols, out var resolvedAddr, out var resolvedSym) &&
                    TryGetStringPreviewAt(resolvedAddr, stringPreview, objects, objBytesByIndex, out var rp) && !string.IsNullOrEmpty(rp))
                {
                    sym = resolvedSym;
                    preview = rp;
                    return true;
                }
            }

            // Immediate literal (0x...)
            if (TryParseImm32(op, out var imm) && TryResolveStringAddressFromRaw(imm, stringSymbols, out var iaddr, out var isym) &&
                TryGetStringPreviewAt(iaddr, stringPreview, objects, objBytesByIndex, out var ip) && !string.IsNullOrEmpty(ip))
            {
                sym = isym;
                preview = ip;
                return true;
            }

            // Embedded literal (e.g. dword [0x4988])
            var hm = HexLiteralRegex.Match(operandText);
            if (hm.Success && TryParseHexUInt(hm.Value, out var rawLit) &&
                TryResolveStringAddressFromRaw(rawLit, stringSymbols, out var haddr, out var hsym) &&
                TryGetStringPreviewAt(haddr, stringPreview, objects, objBytesByIndex, out var hp) && !string.IsNullOrEmpty(hp))
            {
                sym = hsym;
                preview = hp;
                return true;
            }

            return false;
        }

        private static bool TryResolveStringAddressFromRaw(uint raw, Dictionary<uint, string> stringSymbols, out uint addr, out string sym)
        {
            addr = 0;
            sym = string.Empty;
            if (stringSymbols == null || stringSymbols.Count == 0)
                return false;

            if (stringSymbols.TryGetValue(raw, out sym))
            {
                addr = raw;
                return true;
            }

            // Common DOS4GW convention: strings live in C/D/E/F0000 regions and code references them by 16-bit offsets.
            if (raw < 0x10000)
            {
                foreach (var baseAddr in new[] { 0x000C0000u, 0x000D0000u, 0x000E0000u, 0x000F0000u })
                {
                    var candidate = unchecked(baseAddr + raw);
                    if (stringSymbols.TryGetValue(candidate, out sym))
                    {
                        addr = candidate;
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool TryResolveStringFromInstruction(
            List<Instruction> instructions,
            int insIdx,
            string rawInstruction,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            HashSet<uint> resourceGetterTargets,
            out string preview)
        {
            preview = string.Empty;
            if (stringSymbols == null || stringSymbols.Count == 0 || stringPreview == null || stringPreview.Count == 0)
                return false;
            if (string.IsNullOrWhiteSpace(rawInstruction))
                return false;

            var t = rawInstruction.Trim();

            // push <reg>
            if (t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
            {
                var op = t.Substring(5).Trim();
                if (IsRegister32(op) && TryResolveRegisterValueBefore(instructions, insIdx, op, out var addr, resourceGetterTargets) &&
                    TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                {
                    preview = p;
                    return true;
                }

                if (TryParseImm32(op, out var imm) && TryGetStringPreviewAt(imm, stringPreview, objects, objBytesByIndex, out var p2) && !string.IsNullOrEmpty(p2))
                {
                    preview = p2;
                    return true;
                }
            }

            // mov <reg>, 0x...
            if (t.StartsWith("mov ", StringComparison.OrdinalIgnoreCase))
            {
                var parts = t.Substring(4).Split(',');
                if (parts.Length == 2)
                {
                    var dst = parts[0].Trim();
                    var src = parts[1].Trim();
                    if (IsRegister32(dst) && TryParseImm32(src, out var imm) && TryGetStringPreviewAt(imm, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                    {
                        preview = p;
                        return true;
                    }
                }
            }

            // lea <reg>, [<base>+0x<disp>] where base resolves to a constant
            if (t.StartsWith("lea ", StringComparison.OrdinalIgnoreCase))
            {
                // Example: lea eax, [ebx+0x4e]
                var m = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var baseReg = m.Groups["base"].Value;
                    var disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);
                    if (TryResolveRegisterValueBefore(instructions, insIdx, baseReg, out var baseVal, resourceGetterTargets))
                    {
                        var addr = baseVal + disp;
                        if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                        {
                            preview = p;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static bool TryGetStringPreviewAt(uint addr,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out string preview)
        {
            preview = string.Empty;

            if (stringPreview != null && stringPreview.TryGetValue(addr, out var p0) && !string.IsNullOrEmpty(p0))
            {
                preview = p0;
                return true;
            }

            if (TryReadCStringAtLinear(objects, objBytesByIndex, addr, out var p1))
            {
                preview = p1;
                if (stringPreview != null && !stringPreview.ContainsKey(addr))
                    stringPreview[addr] = p1;
                return true;
            }

            return false;
        }

        private static bool TryReadCStringAtLinear(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint addr, out string preview)
        {
            preview = string.Empty;
            if (objects == null || objBytesByIndex == null)
                return false;

            foreach (var obj in objects)
            {
                if (addr < obj.BaseAddress)
                    continue;
                var end = obj.BaseAddress + obj.VirtualSize;
                if (addr >= end)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes) || bytes == null || bytes.Length == 0)
                    return false;

                var start = (int)(addr - obj.BaseAddress);
                if (start < 0 || start >= bytes.Length)
                    return false;

                var maxLen = Math.Min(bytes.Length, (int)Math.Min(obj.VirtualSize, (uint)bytes.Length));
                if (start >= maxLen)
                    return false;

                var i = start;
                var sb = new StringBuilder();
                while (i < maxLen && IsLikelyStringChar(bytes[i]) && sb.Length < 200)
                {
                    sb.Append((char)bytes[i]);
                    i++;
                }

                var nul = (i < maxLen && bytes[i] == 0x00);
                var s = sb.ToString();
                if (!nul || s.Length < 4)
                    return false;
                if (!LooksLikeHumanString(s))
                    return false;

                preview = EscapeForComment(s);
                return true;
            }

            return false;
        }
    }
}
