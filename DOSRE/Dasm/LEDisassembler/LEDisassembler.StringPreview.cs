using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static bool TryReadU32AtLinear(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint addr, out uint value)
        {
            value = 0;
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
                if (start < 0 || start + 4 > bytes.Length)
                    return false;

                var maxLen = Math.Min(bytes.Length, (int)Math.Min(obj.VirtualSize, (uint)bytes.Length));
                if (start + 4 > maxLen)
                    return false;

                value = BitConverter.ToUInt32(bytes, start);
                return true;
            }

            return false;
        }

        private static bool TryResolveStringFromPointerAt(uint ptrAddr,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out uint resolvedAddr,
            out string sym,
            out string preview)
        {
            resolvedAddr = 0;
            sym = string.Empty;
            preview = string.Empty;

            if (!TryReadU32AtLinear(objects, objBytesByIndex, ptrAddr, out var pval))
                return false;

            // Pointer value itself may be a raw offset or a linear address.
            if (stringSymbols != null && TryResolveStringAddressFromRaw(pval, stringSymbols, objects, out var mapped, out var mappedSym))
                resolvedAddr = mapped;
            else
                resolvedAddr = pval;

            if (!TryGetStringPreviewAt(resolvedAddr, stringPreview, objects, objBytesByIndex, out var p) || string.IsNullOrEmpty(p))
                return false;

            preview = p;
            sym = stringSymbols != null
                ? stringSymbols.TryGetValue(resolvedAddr, out var s0) ? s0 : (stringSymbols[resolvedAddr] = $"s_{resolvedAddr:X8}")
                : $"s_{resolvedAddr:X8}";
            return true;
        }

        private static bool TryResolveRegisterStringViaLastWrite(
            List<Instruction> instructions,
            int indexExclusive,
            string reg,
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
            if (instructions == null || indexExclusive <= 0 || !IsRegister32(reg))
                return false;

            var start = Math.Min(indexExclusive - 1, instructions.Count - 1);
            var stop = Math.Max(0, start - 64);

            for (var i = start; i >= stop; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                // Stop at control-flow barriers.
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov reg, [0xADDR]
                var mm0 = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*(?:dword\s+)?\[(?<addr>0x[0-9a-fA-F]{{1,8}})\]$", RegexOptions.IgnoreCase);
                if (mm0.Success && TryParseImm32(mm0.Groups["addr"].Value, out var paddr) &&
                    TryResolveStringFromPointerAt(paddr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var s0, out var p0))
                {
                    sym = s0;
                    preview = p0;
                    return true;
                }

                // mov reg, [g_XXXXXXXX]
                var mmg = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*(?:dword\s+)?\[(?<g>g_[0-9a-fA-F]{{8}})\]$", RegexOptions.IgnoreCase);
                if (mmg.Success)
                {
                    var gtok = mmg.Groups["g"].Value;
                    var hex = gtok.Substring(2);
                    var gaddr = Convert.ToUInt32(hex, 16);
                    if (TryResolveStringFromPointerAt(gaddr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var sg, out var pg))
                    {
                        sym = sg;
                        preview = pg;
                        return true;
                    }
                }

                // mov reg, [baseReg(+disp)]
                var mm1 = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*(?:dword\s+)?\[(?<base>e[a-z]{{2}})(?<disp>\+0x[0-9a-fA-F]{{1,8}})?\]$", RegexOptions.IgnoreCase);
                if (mm1.Success)
                {
                    var baseReg = mm1.Groups["base"].Value.ToLowerInvariant();
                    var disp = 0u;
                    if (mm1.Groups["disp"].Success)
                        TryParseImm32("0x" + mm1.Groups["disp"].Value.Substring(3), out disp); // +0xNNN -> 0xNNN

                    if (TryResolveRegisterValueBefore(instructions, i, baseReg, out var baseVal, resourceGetterTargets))
                    {
                        var addr = unchecked(baseVal + disp);
                        if (TryResolveStringFromPointerAt(addr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var s1, out var p1))
                        {
                            sym = s1;
                            preview = p1;
                            return true;
                        }
                    }
                }
            }

            return false;
        }

        private static string TryInlineStringPreview(string insText,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            List<Instruction> instructions,
            int insIdx,
            Dictionary<uint, string> stringSymbols,
            HashSet<uint> resourceGetterTargets)
        {
            if (string.IsNullOrEmpty(insText) || stringPreview == null)
                return string.Empty;

            // NOTE: insText is the *rendered* line (often including address/bytes prefix).
            // Use the raw instruction text for mnemonic checks to avoid missing matches.
            var rawText = (instructions != null && insIdx >= 0 && insIdx < instructions.Count)
                ? InsText(instructions[insIdx])
                : insText;

            // Keep this conservative to avoid spam.
            var lower = rawText.TrimStart();
            if (!lower.StartsWith("push ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("lea ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("mov ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("add ", StringComparison.OrdinalIgnoreCase) &&
                !lower.StartsWith("sub ", StringComparison.OrdinalIgnoreCase))
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

            if (TryResolveStringFromInstruction(instructions, insIdx, rawText, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var p1))
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

            if (stringPreview == null)
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
            if (!string.IsNullOrEmpty(rdirect) && TryParseResourceSym(rdirect, out var rdaddr))
            {
                if (TryResolveStringAddressFromRaw(rdaddr, stringSymbols, objects, out var resolvedAddr, out var resolvedSym) &&
                    TryGetStringPreviewAt(resolvedAddr, stringPreview, objects, objBytesByIndex, out var rp) && !string.IsNullOrEmpty(rp))
                {
                    sym = resolvedSym;
                    preview = rp;
                    return true;
                }
            }

            var op = operandText.Trim();

            // Register operand (e.g. push eax)
            if (IsRegister32(op) && TryResolveRegisterValueBefore(instructions, callIdx, op, out var raddr, resourceGetterTargets))
            {
                if (stringSymbols != null && TryResolveStringAddressFromRaw(raddr, stringSymbols, objects, out var resolvedAddr, out var resolvedSym) &&
                    TryGetStringPreviewAt(resolvedAddr, stringPreview, objects, objBytesByIndex, out var rp) && !string.IsNullOrEmpty(rp))
                {
                    sym = resolvedSym;
                    preview = rp;
                    return true;
                }

                // Fallback: treat the resolved register value as a direct linear address.
                if (TryGetStringPreviewAt(raddr, stringPreview, objects, objBytesByIndex, out var rp2) && !string.IsNullOrEmpty(rp2))
                {
                    sym = stringSymbols != null
                        ? stringSymbols.TryGetValue(raddr, out var s0) ? s0 : (stringSymbols[raddr] = $"s_{raddr:X8}")
                        : $"s_{raddr:X8}";
                    preview = rp2;
                    return true;
                }

                // One level of pointer indirection: reg contains address of a pointer-to-string.
                if (TryResolveStringFromPointerAt(raddr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var psym, out var pprev))
                {
                    sym = psym;
                    preview = pprev;
                    return true;
                }
            }

            // Register operand but not tracked as a constant: try to resolve via last-write dereference patterns.
            if (IsRegister32(op) && TryResolveRegisterStringViaLastWrite(instructions, callIdx, op.ToLowerInvariant(), stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var wsym, out var wprev))
            {
                sym = wsym;
                preview = wprev;
                return true;
            }

            // Immediate literal (0x...)
            if (TryParseImm32(op, out var imm) && stringSymbols != null && TryResolveStringAddressFromRaw(imm, stringSymbols, objects, out var iaddr, out var isym) &&
                TryGetStringPreviewAt(iaddr, stringPreview, objects, objBytesByIndex, out var ip) && !string.IsNullOrEmpty(ip))
            {
                sym = isym;
                preview = ip;
                return true;
            }

            // Fallback: immediate might already be a linear address.
            if (TryParseImm32(op, out var imm2) && TryGetStringPreviewAt(imm2, stringPreview, objects, objBytesByIndex, out var ip2) && !string.IsNullOrEmpty(ip2))
            {
                sym = stringSymbols != null
                    ? stringSymbols.TryGetValue(imm2, out var s1) ? s1 : (stringSymbols[imm2] = $"s_{imm2:X8}")
                    : $"s_{imm2:X8}";
                preview = ip2;
                return true;
            }

            // Immediate as pointer-to-string location (e.g., passing &g_ptr where g_ptr points at a string).
            if (TryParseImm32(op, out var immPtr) && TryResolveStringFromPointerAt(immPtr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var isym2, out var ip3))
            {
                sym = isym2;
                preview = ip3;
                return true;
            }

            // Embedded literal (e.g. dword [0x4988])
            var hm = HexLiteralRegex.Match(operandText);
            if (hm.Success && TryParseHexUInt(hm.Value, out var rawLit) &&
                stringSymbols != null && TryResolveStringAddressFromRaw(rawLit, stringSymbols, objects, out var haddr, out var hsym) &&
                TryGetStringPreviewAt(haddr, stringPreview, objects, objBytesByIndex, out var hp) && !string.IsNullOrEmpty(hp))
            {
                sym = hsym;
                preview = hp;
                return true;
            }

            // Fallback: embedded literal might already be a linear address.
            if (hm.Success && TryParseHexUInt(hm.Value, out var rawLit2) &&
                TryGetStringPreviewAt(rawLit2, stringPreview, objects, objBytesByIndex, out var hp2) && !string.IsNullOrEmpty(hp2))
            {
                sym = stringSymbols != null
                    ? stringSymbols.TryGetValue(rawLit2, out var s2) ? s2 : (stringSymbols[rawLit2] = $"s_{rawLit2:X8}")
                    : $"s_{rawLit2:X8}";
                preview = hp2;
                return true;
            }

            // Embedded literal as pointer-to-string location.
            if (hm.Success && TryParseHexUInt(hm.Value, out var rawPtr) &&
                TryResolveStringFromPointerAt(rawPtr, stringSymbols, stringPreview, objects, objBytesByIndex, out _, out var psym2, out var pprev2))
            {
                sym = psym2;
                preview = pprev2;
                return true;
            }

            return false;
        }

        private static bool TryResolveStringAddressFromRaw(uint raw, Dictionary<uint, string> stringSymbols, List<LEObject> objects, out uint addr, out string sym)
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

            // Common DOS4GW convention: strings live in C/D/E/F0000-ish regions and code references them by 16-bit offsets.
            // Heuristic: check if this raw value is an offset into any object (or typical segment bases) that resolves to a string.
            // IMPORTANT: avoid treating NULL / tiny constants as string offsets, but do allow small offsets when they
            // actually map to a known string symbol.
            if (raw >= 0x10 && raw < 0x20000)
            {
                if (objects != null)
                {
                    foreach (var obj in objects)
                    {
                        var candidate = unchecked(obj.BaseAddress + raw);
                        if (stringSymbols.TryGetValue(candidate, out sym))
                        {
                            addr = candidate;
                            return true;
                        }
                    }
                }

                // Fallback: common 64KB-aligned bases used by Watcom/DOS4GW outputs.
                // Many programs treat pointers as 16-bit offsets relative to a segment base like 0x20000, 0x30000, etc.
                // We only accept the mapping if it lands on a known string address.
                for (var baseAddr = 0x00010000u; baseAddr <= 0x000F0000u; baseAddr += 0x00010000u)
                {
                    var candidate = unchecked(baseAddr + raw);
                    if (stringSymbols.TryGetValue(candidate, out sym))
                    {
                        addr = candidate;
                        return true;
                    }
                }

                // Legacy: also try common higher bases seen in some DOS4GW layouts.
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
            if (stringPreview == null)
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
                // Support multiple variants: [reg+disp], [reg-disp], [reg]
                var m = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})(?:\s*(?<sign>[\+\-])\s*(?<disp>0x[0-9a-fA-F]+|[0-9]+))?\]$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var baseReg = m.Groups["base"].Value;
                    var sign = m.Groups["sign"].Value;
                    var dispStr = m.Groups["disp"].Value;
                    uint disp = 0;
                    if (!string.IsNullOrEmpty(dispStr))
                    {
                        if (dispStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                            disp = Convert.ToUInt32(dispStr[2..], 16);
                        else
                            disp = Convert.ToUInt32(dispStr);
                    }

                    if (TryResolveRegisterValueBefore(instructions, insIdx, baseReg, out var baseVal, resourceGetterTargets))
                    {
                        var addr = sign == "-" ? unchecked(baseVal - disp) : unchecked(baseVal + disp);
                        if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                        {
                            preview = p;
                            return true;
                        }
                    }
                }
            }

            // add/sub <reg>, 0x...
            if (t.StartsWith("add ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub ", StringComparison.OrdinalIgnoreCase))
            {
                var isSub = t.StartsWith("sub ", StringComparison.OrdinalIgnoreCase);
                var parts = t.Substring(4).Split(',');
                if (parts.Length == 2)
                {
                    var dst = parts[0].Trim();
                    var src = parts[1].Trim();
                    if (IsRegister32(dst) && TryParseImm32(src, out var imm))
                    {
                        // 1) Check if dst already has a base value
                        if (TryResolveRegisterValueBefore(instructions, insIdx, dst, out var baseVal, resourceGetterTargets))
                        {
                            var addr = isSub ? unchecked(baseVal - imm) : unchecked(baseVal + imm);
                            if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                            {
                                preview = p;
                                return true;
                            }
                        }

                        // 2) Also check if imm itself is a "naked" offset that resolves to a string in ANY object.
                        // (Usually only for add)
                        if (!isSub && TryResolveStringAddressFromRaw(imm, stringSymbols, objects, out var naddr, out var nsym))
                        {
                            if (TryGetStringPreviewAt(naddr, stringPreview, objects, objBytesByIndex, out var p) && !string.IsNullOrEmpty(p))
                            {
                                preview = p;
                                return true;
                            }
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
