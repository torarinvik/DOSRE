using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static string TryAnnotateDispatchTableCall(
            List<Instruction> instructions,
            int callIdx,
            Dictionary<uint, string> globalSymbols,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> dispatchTableNotes,
            Dictionary<uint, string> dispatchTableSymbols)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = InsText(instructions[callIdx]).Trim();
            var mc = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9a-fA-F]+))?\]$", RegexOptions.IgnoreCase);
            if (!mc.Success)
                return string.Empty;

            var callBase = mc.Groups["base"].Value.ToLowerInvariant();
            var callDisp = 0u;
            if (mc.Groups["disp"].Success)
                callDisp = Convert.ToUInt32(mc.Groups["disp"].Value, 16);

            // Look back for an indexed table load into the call base register, e.g.:
            //   mov edx, [edx*4+0xc3040]
            //   mov eax, [ecx+edx*4+0xNN]
            // (We mainly care about a constant base because that implies a dispatch table.)
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 6; i--)
            {
                var t = InsText(instructions[i]).Trim();

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov dst, [idx*scale + 0xBASE]
                var m1 = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<idx>e[a-z]{2})\*(?<scale>[1248])\+0x(?<base>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (!m1.Success)
                {
                    // mov dst, [base+idx*scale+0xDISP]
                    m1 = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<basereg>e[a-z]{2})\+(?<idx>e[a-z]{2})\*(?<scale>[1248])\+0x(?<base>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                }
                if (!m1.Success)
                    continue;

                var dst = m1.Groups["dst"].Value.ToLowerInvariant();
                if (dst != callBase)
                    continue;

                var idxReg = m1.Groups["idx"].Value.ToLowerInvariant();
                var scale = Convert.ToInt32(m1.Groups["scale"].Value, 10);
                var baseHex = m1.Groups["base"].Value;
                if (!TryParseHexUInt("0x" + baseHex, out var baseAddrU))
                    continue;
                var baseAddr = (uint)baseAddrU;

                if (dispatchTableSymbols != null && !dispatchTableSymbols.ContainsKey(baseAddr))
                {
                    if (objects != null && TryMapLinearToObject(objects, baseAddr, out var _, out var _))
                        dispatchTableSymbols[baseAddr] = $"dtbl_{baseAddr:X8}";
                }

                var baseSym = dispatchTableSymbols != null && dispatchTableSymbols.TryGetValue(baseAddr, out var dt) ? dt :
                    (globalSymbols != null && globalSymbols.TryGetValue(baseAddr, out var gs) ? gs : $"0x{baseAddr:X8}");

                // If the call is through [reg+disp], note it as a secondary deref (often vtbl slot or struct member).
                var callMem = callDisp != 0 ? $"[{callBase}+0x{callDisp:X}]" : $"[{callBase}]";

                // Probe table if it resides in-module; cache per base.
                string tableNote = null;
                if (dispatchTableNotes != null && dispatchTableNotes.TryGetValue(baseAddr, out var cached))
                {
                    tableNote = cached;
                }
                else
                {
                    tableNote = string.Empty;
                    if (objects != null && objBytesByIndex != null && TryMapLinearToObject(objects, baseAddr, out var _, out var _))
                    {
                        var inModule = 0;
                        var samples = 0;
                        var exampleTargets = new List<uint>();
                        for (var k = 0; k < 64; k++)
                        {
                            var entryAddr = unchecked(baseAddr + (uint)(k * 4));
                            if (!TryReadDwordAtLinear(objects, objBytesByIndex, entryAddr, out var val) || val == 0)
                                continue;
                            samples++;
                            if (TryMapLinearToObject(objects, val, out var _, out var _))
                            {
                                inModule++;
                                if (exampleTargets.Count < 4)
                                    exampleTargets.Add(val);
                            }
                        }

                        if (samples > 0)
                        {
                            tableNote = $" ptrs~{inModule}/{samples}";
                            if (exampleTargets.Count > 0)
                                tableNote += $" ex={string.Join(",", exampleTargets.Select(x => $"0x{x:X8}"))}";
                        }
                    }

                    if (dispatchTableNotes != null)
                        dispatchTableNotes[baseAddr] = tableNote;
                }

                // This is best-effort: we don't know the runtime index value.
                return $"DISPATCH?: tbl={baseSym} idx={idxReg} scale={scale}{tableNote} -> {callMem}";
            }

            return string.Empty;
        }

        private static string TryResolveEdxBefore(List<Instruction> instructions, int idx)
        {
            return TryResolveRegBefore("edx", instructions, idx);
        }

        private static string TryResolveEsiBefore(List<Instruction> instructions, int idx)
        {
            return TryResolveRegBefore("esi", instructions, idx);
        }

        private static string TryResolveRegBefore(string reg, List<Instruction> instructions, int idx)
        {
            if (instructions == null)
                return string.Empty;

            var movPrefix = "mov " + reg + ",";
            var leaPrefix = "lea " + reg + ",";

            for (var i = idx - 1; i >= 0 && i >= idx - 12; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.Length == 0) continue;

                if (t.StartsWith(movPrefix, StringComparison.OrdinalIgnoreCase) || t.StartsWith(leaPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    var p = t.IndexOf(',');
                    if (p >= 0 && p + 1 < t.Length)
                        return t.Substring(p + 1).Trim();
                }

                if (t.StartsWith("int ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            return string.Empty;
        }

        private static string TryFormatPointerDetail(string reg, string operand, Dictionary<uint, string> stringSymbols, Dictionary<uint, string> stringPreview, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex)
        {
            if (string.IsNullOrWhiteSpace(operand))
                return string.Empty;

            var op = operand.Trim();
            var regU = reg.ToUpperInvariant();

            // If it is a known string symbol, show preview.
            if (StringSymRegex.IsMatch(op))
            {
                var hex = op.Substring(2);
                if (TryParseHexUInt(hex, out var addr))
                {
                    var prev = stringPreview != null && stringPreview.TryGetValue(addr, out var p) ? p : string.Empty;

                    // FALLBACK: On-demand extraction if not in preview
                    if (string.IsNullOrEmpty(prev))
                        prev = TryExtractStringFromObjects(addr, objects, objBytesByIndex);

                    if (!string.IsNullOrEmpty(prev))
                        return $"{regU}={op} \"{prev}\"";
                    return $"{regU}={op}";
                }
                return $"{regU}={op}";
            }

            // Immediate linear address.
            if (TryParseHexUInt(op, out var imm))
            {
                string sym = null;
                string prev = null;

                if (stringSymbols != null && stringSymbols.TryGetValue(imm, out sym))
                {
                    if (stringPreview != null) stringPreview.TryGetValue(imm, out prev);
                }
                else
                {
                    if (stringPreview != null) stringPreview.TryGetValue(imm, out prev);
                }

                // FALLBACK: On-demand extraction
                if (string.IsNullOrEmpty(prev))
                    prev = TryExtractStringFromObjects(imm, objects, objBytesByIndex);

                if (!string.IsNullOrEmpty(prev))
                {
                    var label = sym ?? $"0x{imm:X8}";
                    return $"{regU}={label} \"{prev}\"";
                }

                if (!string.IsNullOrEmpty(sym))
                    return $"{regU}={sym}";

                return $"{regU}=0x{imm:X8}";
            }

            return $"{regU}={op}";
        }

        private static string TryExtractStringFromObjects(uint linearAddr, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex)
        {
            if (objects == null || objBytesByIndex == null) return null;

            foreach (var obj in objects)
            {
                if (linearAddr >= obj.RelocBaseAddr && linearAddr < obj.RelocBaseAddr + obj.VirtualSize)
                {
                    if (objBytesByIndex.TryGetValue(obj.ObjectNumber, out var bytes))
                    {
                        uint relativeOffset = linearAddr - obj.RelocBaseAddr;
                        return ExtractString(bytes, (int)relativeOffset);
                    }
                    break;
                }
            }
            return null;
        }

        private static string ExtractString(byte[] bytes, int offset)
        {
            if (bytes == null || offset < 0 || offset >= bytes.Length) return null;

            int len = 0;
            while (offset + len < bytes.Length && len < 128)
            {
                byte b = bytes[offset + len];
                if (b == 0) break;
                if (b < 32 || b > 126) // Simple ASCII filter
                {
                    if (len > 0) break; // End string at first non-ascii if we have some content
                    return null; // Don't start with non-ascii
                }
                len++;
            }

            if (len < 1) return null;

            try
               {
                return Encoding.ASCII.GetString(bytes, offset, len);
            }
            catch { return null; }
        }

        private static bool TryReadDwordAtLinear(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint addr, out uint value)
        {
            value = 0;
            if (objects == null || objBytesByIndex == null)
                return false;

            if (!TryMapLinearToObject(objects, addr, out var objIndex, out var off))
                return false;

            if (!objBytesByIndex.TryGetValue(objIndex, out var bytes) || bytes == null)
                return false;

            var ioff = (int)off;
            if (ioff < 0 || ioff + 4 > bytes.Length)
                return false;

            value = ReadLEUInt32(bytes, ioff);
            return true;
        }

        private static bool TryDetectVirtualCallSite(List<Instruction> instructions, int callIdx, out string vtblReg, out uint slot, out string thisReg)
        {
            vtblReg = string.Empty;
            slot = 0;
            thisReg = string.Empty;

            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return false;

            var callText = InsText(instructions[callIdx]).Trim();
            var m = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9a-fA-F]+))?\]$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            vtblReg = m.Groups["base"].Value.ToLowerInvariant();
            if (m.Groups["disp"].Success)
                slot = Convert.ToUInt32(m.Groups["disp"].Value, 16);

            // Exclude stack-based indirect calls; those are rarely C++ vtables.
            if (vtblReg == "esp" || vtblReg == "ebp")
                return false;

            // Look back for: mov vtblReg, [thisReg]
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 8; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                var mm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<src>e[a-z]{2})\]$", RegexOptions.IgnoreCase);
                if (mm.Success)
                {
                    var dst = mm.Groups["dst"].Value.ToLowerInvariant();
                    var src = mm.Groups["src"].Value.ToLowerInvariant();
                    if (dst == vtblReg)
                    {
                        // Avoid treating stack-frame registers as a real "this" pointer.
                        if (src != "esp" && src != "ebp")
                            thisReg = src;
                        break;
                    }
                }
            }

            return true;
        }

        private static bool TryResolveRegisterAsTablePointer(
            List<Instruction> instructions,
            int callIdx,
            string reg,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out uint tablePtr,
            out string source)
        {
            tablePtr = 0;
            source = string.Empty;
            if (instructions == null || callIdx <= 0 || string.IsNullOrEmpty(reg))
                return false;

            // Scan backwards for a defining assignment to the base reg.
            // We mainly want: mov reg, [abs] (global pointer) or mov reg, imm32.
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 16; i--)
            {
                var t = InsText(instructions[i]).Trim();

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov reg, 0xXXXXXXXX
                var mi = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*(?<imm>0x[0-9a-fA-F]{{1,8}})$", RegexOptions.IgnoreCase);
                if (mi.Success && TryParseImm32(mi.Groups["imm"].Value, out var imm) && imm != 0)
                {
                    tablePtr = imm;
                    source = "imm";
                    return true;
                }

                // mov reg, [0xXXXXXXXX]
                var ma = Regex.Match(t, $@"^mov\s+{Regex.Escape(reg)},\s*\[(?<addr>0x[0-9a-fA-F]{{1,8}})\]$", RegexOptions.IgnoreCase);
                if (ma.Success && TryParseImm32(ma.Groups["addr"].Value, out var addr) && addr != 0)
                {
                    if (TryReadDwordAtLinear(objects, objBytesByIndex, addr, out var ptr) && ptr != 0)
                    {
                        tablePtr = ptr;
                        source = $"[{addr:X8}]";
                        return true;
                    }
                    break;
                }

                // lea reg, [0xXXXXXXXX]
                var la = Regex.Match(t, $@"^lea\s+{Regex.Escape(reg)},\s*\[(?<addr>0x[0-9a-fA-F]{{1,8}})\]$", RegexOptions.IgnoreCase);
                if (la.Success && TryParseImm32(la.Groups["addr"].Value, out var leaAddr) && leaAddr != 0)
                {
                    tablePtr = leaAddr;
                    source = "lea";
                    return true;
                }

                // If we see the base register being assigned in some other way, stop.
                // Otherwise we'd risk picking an older (stale) definition and inventing nonsense table pointers.
                if (Regex.IsMatch(t, $@"^(mov|lea)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^(pop|xchg)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase) ||
                    Regex.IsMatch(t, $@"^(xor|sub|add|and|or|imul|shl|shr|sar)\s+{Regex.Escape(reg)}\b", RegexOptions.IgnoreCase))
                {
                    break;
                }
            }

            return false;
        }

        private static bool TryFindVtableWriteForThis(
            List<Instruction> instructions,
            int callIdx,
            string thisReg,
            List<LEObject> objects,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            out uint vtblAddr)
        {
            vtblAddr = 0;
            if (instructions == null || callIdx <= 0 || string.IsNullOrEmpty(thisReg))
                return false;

            // Typical ctor: mov dword [ecx], 0xXXXXXXXX
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 64; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    break;

                var m = Regex.Match(t, $@"^mov\s+(?:dword\s+)?\[{Regex.Escape(thisReg)}\],\s*(?<imm>0x[0-9a-fA-F]{{1,8}})$", RegexOptions.IgnoreCase);
                if (m.Success && TryParseImm32(m.Groups["imm"].Value, out var imm))
                {
                    // If the immediate is non-zero, accept it directly.
                    if (imm != 0)
                    {
                        vtblAddr = imm;
                        return true;
                    }

                    // Otherwise, consult fixups for this instruction (common in LE: placeholder imm32 + relocation).
                    var insAddr = (uint)instructions[i].Offset;
                    if (fixupsByInsAddr != null && fixupsByInsAddr.TryGetValue(insAddr, out var fx) && fx != null && fx.Count > 0)
                    {
                        foreach (var f in fx)
                        {
                            // Prefer resolved 32-bit values when available.
                            if (f.Value32.HasValue)
                            {
                                var cand = f.Value32.Value;
                                if (cand != 0 && TryMapLinearToObject(objects, cand, out var _, out var _))
                                {
                                    vtblAddr = cand;
                                    return true;
                                }
                            }

                            // Fallback: use object+offset mapping when present.
                            if (objects != null && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                            {
                                var objIndex = f.TargetObject.Value;
                                if (objIndex >= 1 && objIndex <= objects.Count)
                                {
                                    var cand2 = unchecked(objects[objIndex - 1].BaseAddress + f.TargetOffset.Value);
                                    if (cand2 != 0)
                                    {
                                        vtblAddr = cand2;
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }

        private static string TryAnnotateVirtualCallDetailed(
            List<Instruction> instructions,
            int callIdx,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            Dictionary<uint, string> vtblSymbols,
            Dictionary<uint, Dictionary<uint, uint>> vtblSlots)
        {
            if (!TryDetectVirtualCallSite(instructions, callIdx, out var vtblReg, out var slot, out var thisReg))
                return string.Empty;

            // Path A: true C++-style vcall (vtblReg loaded from [thisReg]).
            uint vtblAddr = 0;
            var haveThis = !string.IsNullOrEmpty(thisReg) && IsRegister32(thisReg);
            if (haveThis)
            {
                // Try to infer the concrete vtbl address from a nearby constructor-style write.
                TryFindVtableWriteForThis(instructions, callIdx, thisReg, objects, fixupsByInsAddr, out vtblAddr);
            }

            // Path B: table call where vtblReg is resolved from a recent global/immediate load.
            // This catches patterns like: mov eax, [abs_ptr] ; call [eax+0xC]
            if (vtblAddr == 0)
            {
                if (TryResolveRegisterAsTablePointer(instructions, callIdx, vtblReg, objects, objBytesByIndex, out var tablePtr, out var source))
                {
                    // Only promote it to a named vtable when the pointer is inside the module image.
                    var inModule = TryMapLinearToObject(objects, tablePtr, out var tblObj, out var tblOff);
                    if (!inModule)
                    {
                        // Still emit a useful hint for runtime function tables without polluting the vtable summary.
                        return $"VCALL?: table=0x{tablePtr:X8} (runtime) slot=0x{slot:X} (base={vtblReg} via {source})";
                    }

                    vtblAddr = tablePtr;
                    if (vtblSymbols != null && !vtblSymbols.ContainsKey(vtblAddr))
                        vtblSymbols[vtblAddr] = $"vtbl_{vtblAddr:X8}";

                    uint target2 = 0;
                    if (slot % 4 == 0 && TryReadDwordAtLinear(objects, objBytesByIndex, unchecked(vtblAddr + slot), out var fnPtr2) &&
                        TryMapLinearToObject(objects, fnPtr2, out var fnObj2, out var fnOff2))
                    {
                        var obj2 = objects.FirstOrDefault(o => o.Index == fnObj2);
                        var isExec2 = obj2.Index != 0 && (obj2.Flags & 0x0004) != 0;
                        if (isExec2)
                            target2 = fnPtr2;
                    }

                    if (target2 != 0)
                    {
                        if (vtblSlots != null)
                        {
                            if (!vtblSlots.TryGetValue(vtblAddr, out var slots2))
                                vtblSlots[vtblAddr] = slots2 = new Dictionary<uint, uint>();
                            if (!slots2.ContainsKey(slot))
                                slots2[slot] = target2;
                        }

                        var tableSymResolved = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vsTableResolved) ? vsTableResolved : $"0x{vtblAddr:X8}";
                        return $"VCALL: table={tableSymResolved} slot=0x{slot:X} -> func_{target2:X8} (base={vtblReg} via {source})";
                    }

                    var tableSymUnresolved = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vsTableUnresolved) ? vsTableUnresolved : $"0x{vtblAddr:X8}";
                    return $"VCALL?: table={tableSymUnresolved} slot=0x{slot:X} (base={vtblReg} via {source})";
                }
            }

            // If we still don't have a concrete vtbl address, only emit a soft hint for true vcall sites.
            if (vtblAddr == 0)
            {
                if (!haveThis)
                    return string.Empty;

                var thisHint0 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                return slot != 0
                    ? $"VCALL?: {thisHint0} vtbl=[{thisReg}] slot=0x{slot:X}"
                    : $"VCALL?: {thisHint0} vtbl=[{thisReg}]";
            }

            // Validate vtblAddr is in-module.
            if (!TryMapLinearToObject(objects, vtblAddr, out var vtblObj, out var vtblOff))
            {
                var thisHint1 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                return $"VCALL?: {thisHint1} vtbl=0x{vtblAddr:X8} slot=0x{slot:X}";
            }

            if (vtblSymbols != null && !vtblSymbols.ContainsKey(vtblAddr))
                vtblSymbols[vtblAddr] = $"vtbl_{vtblAddr:X8}";

            uint target = 0;
            if (slot % 4 == 0 && TryReadDwordAtLinear(objects, objBytesByIndex, unchecked(vtblAddr + slot), out var fnPtr) &&
                TryMapLinearToObject(objects, fnPtr, out var fnObj, out var fnOff))
            {
                // Prefer executable targets.
                var obj = objects.FirstOrDefault(o => o.Index == fnObj);
                var isExec = obj.Index != 0 && (obj.Flags & 0x0004) != 0;
                if (isExec)
                    target = fnPtr;
            }

            if (target != 0)
            {
                if (vtblSlots != null)
                {
                    if (!vtblSlots.TryGetValue(vtblAddr, out var slots))
                        vtblSlots[vtblAddr] = slots = new Dictionary<uint, uint>();
                    if (!slots.ContainsKey(slot))
                        slots[slot] = target;
                }

                var thisHint2 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
                var vtblSym = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vs) ? vs : $"0x{vtblAddr:X8}";
                return $"VCALL: {thisHint2} vtbl={vtblSym} slot=0x{slot:X} -> func_{target:X8}";
            }

            var thisHint3 = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
            var vtblSym2 = vtblSymbols != null && vtblSymbols.TryGetValue(vtblAddr, out var vs2) ? vs2 : $"0x{vtblAddr:X8}";
            return $"VCALL?: {thisHint3} vtbl={vtblSym2} slot=0x{slot:X}";
        }
        private static string TryAnnotateFormatCall(List<Instruction> instructions, int callIdx,
            Dictionary<uint, string> globalSymbols,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> resourceSymbols = null,
            HashSet<uint> resourceGetterTargets = null)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callIns = instructions[callIdx];
            var callText = InsText(callIns);
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Collect pushes immediately preceding this call.
            // In cdecl-style code, the format string is often the *last* push before the call.
            var pushedOperands = new List<string>();
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 16; i--)
            {
                var t = InsText(instructions[i]);

                // stop at barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                if (t.StartsWith("add esp", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub esp", StringComparison.OrdinalIgnoreCase))
                    break;

                if (!t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                    continue;

                t = RewriteKnownAddressLiterals(t, globalSymbols, stringSymbols, resourceSymbols);
                pushedOperands.Add(t.Substring(5).Trim());
                if (pushedOperands.Count >= 12)
                    break;
            }

            if (pushedOperands.Count == 0)
                return string.Empty;

            // Find any pushed operand that resolves to a known string symbol (prefer a printf-like format).
            string bestSym = string.Empty;
            string bestPreview = string.Empty;
            var bestIsFmt = false;

            for (var k = 0; k < pushedOperands.Count; k++)
            {
                var op = pushedOperands[k];
                if (!TryResolveStringSymFromOperand(instructions, callIdx, op, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var sym, out var preview))
                    continue;

                var isFmt = LooksLikePrintfFormat(preview);
                if (isFmt)
                {
                    bestSym = sym;
                    bestPreview = preview;
                    bestIsFmt = true;
                    break;
                }

                if (string.IsNullOrEmpty(bestSym))
                {
                    bestSym = sym;
                    bestPreview = preview;
                }
            }

            if (string.IsNullOrEmpty(bestSym))
                return string.Empty;

            if (bestIsFmt)
                return $"FMT: printf-like fmt={bestSym} args~{pushedOperands.Count} \"{bestPreview}\"";

            if (!string.IsNullOrEmpty(bestPreview))
                return $"STRCALL: text={bestSym} args~{pushedOperands.Count} \"{bestPreview}\"";

            return $"STRCALL: text={bestSym} args~{pushedOperands.Count}";
        }

        // Heuristic: for CALL sites, try to surface any immediately-pushed string literal arguments.
        // This is intentionally conservative: it only scans a short window and only emits when it can
        // resolve at least one argument to a known (or readable) C-string.
        private static string TryAnnotateCallStringLiteralArgs(List<Instruction> instructions, int callIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            HashSet<uint> resourceGetterTargets = null,
            int maxLookback = 16,
            int maxArgs = 4)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = InsText(instructions[callIdx]).Trim();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Collect pushes immediately preceding this call.
            // Scan backwards; the first push we see is arg0 (cdecl-style: last push before call is first argument).
            var resolved = new List<(string Sym, string Preview)>();

            // Stack-slot argument setup (common when caller reserves an arg area with `sub esp, N`):
            //   mov [esp+0x0], <op>
            //   mov dword [esp+0x4], <op>
            // We store by slot offset, then emit in ascending offset order.
            var stackSlots = new Dictionary<uint, (string Sym, string Preview)>();
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - Math.Max(1, maxLookback); i--)
            {
                var t = InsText(instructions[i]).Trim();

                // Stop at obvious barriers (avoid crossing control flow / stack frame adjustments).
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                    break;

                if (t.StartsWith("add esp", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub esp", StringComparison.OrdinalIgnoreCase))
                    break;

                // Track stack-slot writes for outgoing args: mov [esp+disp], src
                // Keep scanning even if we don't resolve this one.
                // Note: operand order is AT&T-ish? In this output it is Intel: mov dest, src
                var mMovEsp = Regex.Match(t, @"^mov\s+(?:dword\s+)?\[(?<base>esp)(?<disp>\+0x[0-9a-fA-F]{1,8})?\],\s*(?<src>.+)$", RegexOptions.IgnoreCase);
                if (mMovEsp.Success)
                {
                    var disp = mMovEsp.Groups["disp"].Success ? mMovEsp.Groups["disp"].Value.Substring(1) : "0x0"; // drop leading '+'
                    if (TryParseImm32(disp, out var slot))
                    {
                        var src = mMovEsp.Groups["src"].Value.Trim();
                        if (TryResolveStringSymFromOperand(instructions, callIdx, src, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var symMov, out var prevMov) &&
                            !string.IsNullOrEmpty(prevMov))
                        {
                            // Keep the first resolved assignment for this slot in the lookback window.
                            if (!stackSlots.ContainsKey(slot))
                                stackSlots[slot] = (symMov, prevMov);
                        }
                    }
                }

                if (!t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var op = t.Substring(5).Trim();
                if (TryResolveStringSymFromOperand(instructions, callIdx, op, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var sym, out var prev) &&
                    !string.IsNullOrEmpty(prev))
                {
                    resolved.Add((sym, prev));
                    if (resolved.Count >= Math.Max(1, maxArgs))
                        break;
                }
            }

            // Also support register-passed string literals (common in Watcom-style codegen):
            //   mov eax, s_... ; call ...
            // If we got no stack args (or even if we did), try to resolve a few likely arg regs.
            var resolvedRegs = new List<(string Reg, string Sym, string Preview)>();
            foreach (var reg in new[] { "eax", "edx", "ecx", "ebx" })
            {
                if (!TryResolveStringSymFromOperand(instructions, callIdx, reg, stringSymbols, stringPreview, objects, objBytesByIndex, resourceGetterTargets, out var sym, out var prev))
                    continue;
                if (string.IsNullOrEmpty(prev))
                    continue;

                // Avoid duplicating the same (sym/preview) already found via pushes.
                var dup = false;
                for (var k = 0; k < resolved.Count; k++)
                {
                    if (StringComparer.OrdinalIgnoreCase.Equals(resolved[k].Sym, sym) && StringComparer.Ordinal.Equals(resolved[k].Preview, prev))
                    {
                        dup = true;
                        break;
                    }
                }
                if (!dup)
                    resolvedRegs.Add((reg, sym, prev));
            }

            if (resolved.Count == 0 && stackSlots.Count == 0 && resolvedRegs.Count == 0)
                return string.Empty;

            // Emit in arg order: arg0 is the last push before the call.
            var sb = new StringBuilder();
            sb.Append("STRARGS:");
            for (var k = 0; k < resolved.Count; k++)
            {
                var (sym, prev) = resolved[k];
                if (string.IsNullOrEmpty(sym))
                    sym = "(str)";
                sb.Append($" arg{k}={sym} \"{prev}\"");
            }

            if (stackSlots.Count > 0)
            {
                foreach (var kvp in stackSlots.OrderBy(kvp => kvp.Key).Take(Math.Max(0, maxArgs - resolved.Count)))
                {
                    var slot = kvp.Key;
                    var (sym, prev) = kvp.Value;
                    if (string.IsNullOrEmpty(sym))
                        sym = "(str)";
                    sb.Append($" [esp+0x{slot:X}]={sym} \"{prev}\"");
                }
            }

            for (var k = 0; k < resolvedRegs.Count; k++)
            {
                var (reg, sym, prev) = resolvedRegs[k];
                if (string.IsNullOrEmpty(sym))
                    sym = "(str)";
                sb.Append($" {reg}={sym} \"{prev}\"");
            }
            return sb.ToString();
        }

        // Test-friendly wrapper (avoids exposing private LEObject in a public/internal signature).
        internal static string TryAnnotateCallStringLiteralArgsForTest(List<Instruction> instructions, int callIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview)
        {
            return TryAnnotateCallStringLiteralArgs(
                instructions,
                callIdx,
                stringSymbols,
                stringPreview,
                objects: null,
                objBytesByIndex: null,
                resourceGetterTargets: null);
        }

        private static string TryAnnotateCallStackCleanup(List<Instruction> instructions, int callIdx)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = InsText(instructions[callIdx]);
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            if (callIdx + 1 >= instructions.Count)
                return string.Empty;

            var next = InsText(instructions[callIdx + 1]).Trim();

            // Common cdecl cleanup: add esp, 0xNN
            var m = Regex.Match(next, @"^add\s+esp,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return string.Empty;

            if (!TryParseImm32(m.Groups["imm"].Value, out var imm))
                return string.Empty;

            if (imm == 0)
                return string.Empty;

            // Heuristic: args are 4-byte pushes
            var argc = (imm % 4 == 0) ? (imm / 4) : 0;
            return argc > 0
                ? $"ARGC: ~{argc} (stack +0x{imm:X})"
                : $"ARGC: stack +0x{imm:X}";
        }

        private static string TryAnnotateVirtualCall(List<Instruction> instructions, int callIdx)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;

            var callText = InsText(instructions[callIdx]).Trim();
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // Looking for an indirect call through a memory operand:
            //   call dword [eax+0xNN]
            //   call [eax+0xNN]
            // Common C++ virtual pattern in 32-bit:
            //   mov vt, [this]
            //   call [vt+slot]
            var m = Regex.Match(callText, @"^call\s+(?:dword\s+)?\[(?<base>e[a-z]{2})(?<disp>\+0x[0-9a-fA-F]+)?\]$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return string.Empty;

            var baseReg = m.Groups["base"].Value.ToLowerInvariant();
            var dispHex = m.Groups["disp"].Success ? m.Groups["disp"].Value.Substring(1) : string.Empty; // drop leading '+'
            var slot = 0u;
            var haveSlot = !string.IsNullOrEmpty(dispHex) && TryParseImm32(dispHex, out slot);

            // Look back a short window for: mov baseReg, [thisReg]
            string thisReg = null;
            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 6; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // mov eax, [ecx]
                var mm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*\[(?<src>e[a-z]{2})\]$", RegexOptions.IgnoreCase);
                if (mm.Success)
                {
                    var dst = mm.Groups["dst"].Value.ToLowerInvariant();
                    var src = mm.Groups["src"].Value.ToLowerInvariant();
                    if (dst == baseReg)
                    {
                        // Avoid treating stack-frame registers as a real "this" pointer.
                        if (src != "esp" && src != "ebp")
                            thisReg = src;
                        break;
                    }
                }
            }

            // If we couldn't infer a this-reg, still annotate as an indirect call.
            if (string.IsNullOrEmpty(thisReg))
            {
                return haveSlot
                    ? $"VIRT?: call [{baseReg}+0x{slot:X}] (indirect)"
                    : $"VIRT?: call [{baseReg}] (indirect)";
            }

            // Favor C++ thiscall intuition: ECX is often 'this'.
            var thisHint = thisReg == "ecx" ? "this=ecx" : $"this~{thisReg}";
            if (haveSlot)
                return $"VIRT: {thisHint} vtbl=[{thisReg}] slot=0x{slot:X}";
            return $"VIRT: {thisHint} vtbl=[{thisReg}]";
        }

        private static string TryAnnotateResourceStringCall(
            List<Instruction> instructions,
            int callIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> resourceSymbols,
            HashSet<uint> resourceGetterTargets)
        {
            if (instructions == null || callIdx < 0 || callIdx >= instructions.Count)
                return string.Empty;
            if (stringPreview == null)
                return string.Empty;

            var callText = InsText(instructions[callIdx]);
            if (!callText.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            // If we detected specific resource-getter call targets, require this call to match.
            if (resourceGetterTargets != null && resourceGetterTargets.Count > 0)
            {
                var mcall = Regex.Match(callText.Trim(), @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (!mcall.Success || !TryParseHexUInt(mcall.Groups["target"].Value, out var tgt) || !resourceGetterTargets.Contains(tgt))
                    return string.Empty;
            }

            // Look back for the common pattern:
            //   mov eax, imm
            //   add edx, 0xE0000 (or lea edx, [reg+0xE0000])
            //   call ...
            // Treat imm as an offset into the region; if (regionBase+imm) matches an s_ symbol, annotate it.
            uint? offsetImm = null;
            uint? regionBase = null;

            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 12; i--)
            {
                var t = InsText(instructions[i]).Trim();

                // Stop at control-flow barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                var mo = Regex.Match(t, @"^mov\s+e[a-z]{2},\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (offsetImm == null && mo.Success && TryParseImm32(mo.Groups["imm"].Value, out var oi) && oi < 0x10000)
                {
                    offsetImm = oi;
                    continue;
                }

                var ma = Regex.Match(t, @"^add\s+e[a-z]{2},\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && ma.Success && TryParseImm32(ma.Groups["imm"].Value, out var baseImm) && baseImm >= 0x10000)
                {
                    regionBase = baseImm;
                    continue;
                }

                var ml = Regex.Match(t, @"^lea\s+e[a-z]{2},\s*\[e[a-z]{2}\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (regionBase == null && ml.Success)
                {
                    var disp = Convert.ToUInt32(ml.Groups["disp"].Value, 16);
                    if (disp >= 0x10000)
                        regionBase = disp;
                    continue;
                }

                if (offsetImm.HasValue && regionBase.HasValue)
                    break;
            }

            if (!offsetImm.HasValue || !regionBase.HasValue)
                return string.Empty;

            var addr = unchecked(regionBase.Value + offsetImm.Value);
            // Always record a resource symbol for this derived address.
            if (resourceSymbols != null && !resourceSymbols.ContainsKey(addr))
                resourceSymbols[addr] = $"r_{addr:X8}";

            string sym = null;
            var haveStringSym = stringSymbols != null && stringSymbols.TryGetValue(addr, out sym);
            if (TryGetStringPreviewAt(addr, stringPreview, objects, objBytesByIndex, out var prev) && !string.IsNullOrEmpty(prev))
            {
                var kind = LooksLikePrintfFormat(prev) ? "RESFMT" : "RESSTR";
                var label = haveStringSym ? sym : $"r_{addr:X8}";
                return $"{kind}: {label} \"{prev}\" ; RET=eax=r_{addr:X8}";
            }

            // Still useful: show the derived resource address when it points into a typical resource/string region.
            // (Avoid spamming for small constants or unrelated addresses.)
            var rb = regionBase.Value;
            if (rb >= 0x000C0000 && rb <= 0x000F0000 && (rb % 0x10000 == 0))
                return $"RESOFF: base=0x{rb:X} off=0x{offsetImm.Value:X} => r_{addr:X8} ; RET=eax=r_{addr:X8}";

            return string.Empty;
        }
    }
}
