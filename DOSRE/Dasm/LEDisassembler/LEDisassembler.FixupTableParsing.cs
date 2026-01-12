using System;
using System.Collections.Generic;
using System.Linq;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static List<LEFixup> ParseFixupsForWindow(
            LEHeader header,
            List<LEObject> objects,
            uint[] pageMap,
            List<string> importModules,
            byte[] fileBytes,
            uint[] fixupPageOffsets,
            byte[] fixupRecordStream,
            byte[] objBytes,
            LEObject obj,
            uint startLinear,
            uint endLinear)
        {
            // DOS4GW/MS-DOS focused fixup decoder.
            // Empirically, many DOS4GW LEs use a fixed record stride per page (often 8/10/12/16).
            // We use the stride-guessing logic to parse records consistently and then enrich by
            // reading the value at the fixup site and mapping it to an object+offset when it looks
            // like an internal pointer.
            var fixups = new List<LEFixup>();

            if (objBytes == null || objBytes.Length == 0)
                return fixups;

            for (var i = 0; i < obj.PageCount; i++)
            {
                // IMPORTANT: Fixup page table is indexed by the logical page-map entry index,
                // not the physical page number.
                var logicalPageIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (logicalPageIndex0 < 0 || logicalPageIndex0 >= pageMap.Length)
                    break;

                var logicalPageNumber1 = (uint)(logicalPageIndex0 + 1);
                if (logicalPageNumber1 == 0 || logicalPageNumber1 > header.NumberOfPages)
                    continue;

                var physicalPage = pageMap[logicalPageIndex0]; // may be 0
                var pageLinearBase = unchecked(obj.BaseAddress + (uint)(i * header.PageSize));

                // quick window reject
                var pageLinearEnd = unchecked(pageLinearBase + header.PageSize);
                if (pageLinearEnd <= startLinear || pageLinearBase >= endLinear)
                    continue;

                var pageIndex0 = (int)(logicalPageNumber1 - 1);
                if (pageIndex0 < 0 || pageIndex0 + 1 >= fixupPageOffsets.Length)
                    continue;

                var recStart = fixupPageOffsets[pageIndex0];
                var recEnd = fixupPageOffsets[pageIndex0 + 1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                var len = (int)(recEnd - recStart);
                var guess = GuessStride(fixupRecordStream, (int)recStart, len, (int)header.PageSize);
                var stride = guess.Stride;
                if (stride <= 0)
                    stride = 16;

                var entries = len / stride;
                if (entries <= 0)
                    continue;

                // Keep a reasonable cap to avoid pathological pages.
                entries = Math.Min(entries, 4096);

                for (var entry = 0; entry < entries; entry++)
                {
                    var p = (int)recStart + entry * stride;
                    if (p + 4 > (int)recEnd)
                        break;

                    var srcType = fixupRecordStream[p + 0];
                    var flags = fixupRecordStream[p + 1];
                    var srcOff = (ushort)(fixupRecordStream[p + 2] | (fixupRecordStream[p + 3] << 8));
                    if (srcOff >= header.PageSize)
                    {
                        var swapped = (ushort)((srcOff >> 8) | (srcOff << 8));
                        if (swapped < header.PageSize)
                            srcOff = swapped;
                    }
                    var sourceLinear = unchecked(pageLinearBase + srcOff);

                    // Best-effort: read value at/near fixup site from reconstructed object bytes.
                    // Some DOS4GW records appear to point slightly before the relocated field; probing
                    // a few bytes forward greatly reduces false positives (e.g., reading opcode bytes).
                    var objOffset = (int)((uint)i * header.PageSize + srcOff);
                    uint? value32 = null;
                    ushort? value16 = null;
                    int chosenDelta = 0;
                    int? mappedObj = null;
                    uint mappedOff = 0;

                    if (objOffset >= 0)
                    {
                        // Recover small object-relative offsets first (common for DOS4GW resource/string regions like 0xE0000+off).
                        // This avoids accidentally treating opcode+imm byte sequences as in-module pointers.
                        for (var delta = -3; delta <= 3; delta++)
                        {
                            var off = objOffset + delta;
                            if (off < 0)
                                continue;
                            if (off + 4 > objBytes.Length)
                                continue;
                            var v = ReadUInt32(objBytes, off);
                            if (v != 0 && v < 0x10000)
                            {
                                value32 = v;
                                chosenDelta = delta;
                                break;
                            }
                        }

                        // If no small offset candidate, try to find a 32-bit in-module pointer near the fixup site.
                        // Some records point into the middle of an imm32/disp32 field, so probe both backward and forward.
                        if (!value32.HasValue)
                        {
                            for (var delta = -3; delta <= 3; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0)
                                    continue;
                                if (off + 4 > objBytes.Length)
                                    continue;
                                var v = ReadUInt32(objBytes, off);
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff))
                                {
                                    value32 = v;
                                    chosenDelta = delta;
                                    mappedObj = tobj;
                                    mappedOff = toff;
                                    break;
                                }
                            }
                        }

                        // If no mapped pointer found, read the raw dword/word at the original site.
                        if (!value32.HasValue)
                        {
                            if (objOffset + 4 <= objBytes.Length)
                                value32 = ReadUInt32(objBytes, objOffset);
                            else if (objOffset + 2 <= objBytes.Length)
                                value16 = ReadUInt16(objBytes, objOffset);
                        }
                    }

                    // For DOS4GW/MS-DOS game workflows we mostly care about internal pointers.
                    // If we couldn't map a 32-bit value into a known object, it often represents
                    // opcode bytes or plain constants. However, DOS4GW fixups frequently also
                    // carry small object-relative offsets (e.g., into a C/D/E/F0000 string/resource region).
                    if (value32.HasValue && !mappedObj.HasValue && value32.Value >= 0x10000)
                        value32 = null;

                    var desc = $"type=0x{srcType:X2} flags=0x{flags:X2} stride={stride}";

                    if (value32.HasValue)
                    {
                        if (mappedObj.HasValue)
                        {
                            desc += $" site+{chosenDelta} val32=0x{value32.Value:X8} => obj{mappedObj.Value}+0x{mappedOff:X}";
                        }
                        else
                        {
                            // Still useful to print the value when it looks like an in-module linear address.
                            desc += $" val32=0x{value32.Value:X8}";
                        }
                    }
                    else if (value16.HasValue)
                    {
                        desc += $" val16=0x{value16.Value:X4}";
                    }

                    // (Optional) try to interpret import module/proc table if present.
                    // Many DOS4GW games have ImportModuleTableEntries=0, so this often won't apply.
                    if (importModules != null && importModules.Count > 0 && stride >= 10)
                    {
                        // Try a lightweight hint: treat next 2 bytes as module index and next 4 as name offset.
                        if (p + 10 <= (int)recEnd)
                        {
                            var mod = (ushort)(fixupRecordStream[p + 4] | (fixupRecordStream[p + 5] << 8));
                            var procOff = ReadUInt32(fixupRecordStream, p + 6);
                            if (mod > 0 && mod <= importModules.Count)
                            {
                                var modName = importModules[mod - 1];
                                var procName = TryReadImportProcName(fileBytes, header, procOff);
                                if (!string.IsNullOrEmpty(modName) && !string.IsNullOrEmpty(procName))
                                    desc += $" import={modName}!{procName}";
                                else if (!string.IsNullOrEmpty(modName))
                                    desc += $" import={modName}!@0x{procOff:X}";
                            }
                        }
                    }

                    // Only keep fixups within the current disassembly window.
                    if (sourceLinear >= startLinear && sourceLinear < endLinear)
                    {
                        var siteLinear = unchecked(sourceLinear + (uint)chosenDelta);
                        fixups.Add(new LEFixup
                        {
                            SourceLinear = sourceLinear,
                            SourceOffsetInPage = srcOff,
                            PageNumber = physicalPage,
                            SiteLinear = siteLinear,
                            SiteDelta = (sbyte)Math.Min(sbyte.MaxValue, Math.Max(sbyte.MinValue, chosenDelta)),
                            Value32 = value32,
                            TargetObject = mappedObj,
                            TargetOffset = mappedObj.HasValue ? (uint?)mappedOff : null,
                            Type = srcType,
                            Flags = flags
                        });
                    }
                }
            }

            return fixups;
        }

        private static List<LeFixupRecordInfo> ParseFixupTableForObject(
            LEHeader header,
            List<LEObject> objects,
            uint[] pageMap,
            List<string> importModules,
            byte[] fileBytes,
            uint[] fixupPageOffsets,
            byte[] fixupRecordStream,
            byte[] objBytes,
            LEObject obj)
        {
            var fixups = new List<LeFixupRecordInfo>();
            if (objBytes == null || objBytes.Length == 0)
                return fixups;

            static bool TryMapOffsetToUniqueObject(List<LEObject> objs, uint off, out int objIndex, out uint linear)
            {
                objIndex = 0;
                linear = 0;

                if (objs == null || objs.Count == 0)
                    return false;

                // Only accept offsets that fit *uniquely* into exactly one object (by smallest size).
                // This is intentionally conservative to avoid turning random immediates into targets.
                const uint slack = 0x1000;
                uint bestSize = uint.MaxValue;
                int bestObj = 0;
                uint bestBase = 0;

                foreach (var o in objs)
                {
                    if (o.VirtualSize == 0)
                        continue;
                    if (off > unchecked(o.VirtualSize + slack))
                        continue;
                    if (o.BaseAddress == 0)
                        continue;

                    if (o.VirtualSize < bestSize)
                    {
                        bestSize = o.VirtualSize;
                        bestObj = o.Index;
                        bestBase = o.BaseAddress;
                    }
                    else if (o.VirtualSize == bestSize)
                    {
                        // Ambiguous.
                        bestObj = 0;
                    }
                }

                if (bestObj == 0)
                    return false;

                objIndex = bestObj;
                linear = unchecked(bestBase + off);
                return true;
            }

            static bool TryMapOffsetToSingleObjectStrict(List<LEObject> objs, uint off, out int objIndex, out uint linear)
            {
                objIndex = 0;
                linear = 0;

                if (objs == null || objs.Count == 0)
                    return false;

                const uint slack = 0x1000;
                int matches = 0;
                int matchObj = 0;
                uint matchBase = 0;

                foreach (var o in objs)
                {
                    if (o.VirtualSize == 0)
                        continue;
                    if (off > unchecked(o.VirtualSize + slack))
                        continue;
                    if (o.BaseAddress == 0)
                        continue;

                    matches++;
                    matchObj = o.Index;
                    matchBase = o.BaseAddress;

                    if (matches > 1)
                        break;
                }

                if (matches != 1)
                    return false;

                objIndex = matchObj;
                linear = unchecked(matchBase + off);
                return true;
            }

            static ushort Swap16(ushort v) => (ushort)((v >> 8) | (v << 8));

            static bool TryReadU16(byte[] b, int off, int end, out ushort v)
            {
                v = 0;
                if (b == null || off < 0 || off + 2 > end)
                    return false;
                v = (ushort)(b[off] | (b[off + 1] << 8));
                return true;
            }

            static bool TryReadU32(byte[] b, int off, int end, out uint v)
            {
                v = 0;
                if (b == null || off < 0 || off + 4 > end)
                    return false;
                v = (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
                return true;
            }

            static uint ObjBase(List<LEObject> objs, int idx1)
            {
                if (objs == null || idx1 <= 0 || idx1 > objs.Count)
                    return 0;
                return objs[idx1 - 1].BaseAddress;
            }

            static uint ObjSize(List<LEObject> objs, int idx1)
            {
                if (objs == null || idx1 <= 0 || idx1 > objs.Count)
                    return 0;
                return objs[idx1 - 1].VirtualSize;
            }

            for (var i = 0; i < obj.PageCount; i++)
            {
                var logicalPageIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (logicalPageIndex0 < 0 || logicalPageIndex0 >= pageMap.Length)
                    break;

                var logicalPageNumber1 = (uint)(logicalPageIndex0 + 1);
                if (logicalPageNumber1 == 0 || logicalPageNumber1 > header.NumberOfPages)
                    continue;

                var physicalPage = pageMap[logicalPageIndex0];
                var pageLinearBase = unchecked(obj.BaseAddress + (uint)(i * header.PageSize));

                var pageIndex0 = (int)(logicalPageNumber1 - 1);
                if (pageIndex0 < 0 || pageIndex0 + 1 >= fixupPageOffsets.Length)
                    continue;

                var recStart = fixupPageOffsets[pageIndex0];
                var recEnd = fixupPageOffsets[pageIndex0 + 1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                var len = (int)(recEnd - recStart);
                var guess = GuessStride(fixupRecordStream, (int)recStart, len, (int)header.PageSize);
                var stride = guess.Stride > 0 ? guess.Stride : 16;

                var entries = len / stride;
                if (entries <= 0)
                    continue;
                entries = Math.Min(entries, 65536);

                var recEndI = (int)recEnd;
                for (var entry = 0; entry < entries; entry++)
                {
                    var p = (int)recStart + entry * stride;
                    if (p + 4 > recEndI)
                        break;

                    // Constrain parsing to the current record boundary.
                    var recBound = p + stride;
                    if (recBound > recEndI)
                        recBound = recEndI;

                    var srcType = fixupRecordStream[p + 0];
                    var flags = fixupRecordStream[p + 1];
                    var srcOff = (ushort)(fixupRecordStream[p + 2] | (fixupRecordStream[p + 3] << 8));
                    if (srcOff >= header.PageSize)
                    {
                        var swapped = (ushort)((srcOff >> 8) | (srcOff << 8));
                        if (swapped < header.PageSize)
                            srcOff = swapped;
                    }
                    var sourceLinear = unchecked(pageLinearBase + srcOff);

                    // Optional target spec fields inside the record.
                    // IMPORTANT: only read within this record (recBound) to avoid bleeding into the next record when stride < 10.
                    ushort _specU16 = 0;
                    ushort _specU16b = 0;
                    uint _specU32 = 0;
                    var hasSpecU16 = TryReadU16(fixupRecordStream, p + 4, recBound, out _specU16);
                    var hasSpecU16b = TryReadU16(fixupRecordStream, p + 6, recBound, out _specU16b);
                    var hasSpecU32 = TryReadU32(fixupRecordStream, p + 6, recBound, out _specU32);

                    string targetKind = "unknown";
                    int? targetObj = null;
                    uint? targetOff = null;
                    uint? targetLinear = null;
                    ushort? importModIdx = null;
                    string importModName = null;
                    uint? importProcNameOff = null;
                    string importProcName = null;

                    if (hasSpecU16 && hasSpecU32)
                    {
                        // Prefer internal object targets when plausible.
                        if (_specU16 >= 1 && _specU16 <= objects.Count)
                        {
                            var sz = ObjSize(objects, _specU16);
                            if (sz == 0 || _specU32 <= sz + 0x1000)
                            {
                                targetKind = "internal";
                                targetObj = _specU16;
                                targetOff = _specU32;
                                var baseAddr = ObjBase(objects, _specU16);
                                if (baseAddr != 0)
                                    targetLinear = unchecked(baseAddr + _specU32);
                            }
                        }

                        // Fallback: import target
                        if (targetKind == "unknown" && importModules != null && importModules.Count > 0 && _specU16 >= 1 && _specU16 <= importModules.Count)
                        {
                            importModIdx = _specU16;
                            importModName = importModules[_specU16 - 1];
                            importProcNameOff = _specU32;
                            importProcName = TryReadImportProcName(fileBytes, header, _specU32);
                            if (!string.IsNullOrWhiteSpace(importModName))
                                targetKind = "import";
                        }
                    }

                    // Some record families appear to encode the target object index in the low byte of specU16,
                    // and the object-relative offset in specU16b. Decode only when the object index is explicit
                    // and in-range.
                    if (targetKind == "unknown" && hasSpecU16 && hasSpecU16b)
                    {
                        if (srcType == 0x07 && flags == 0x10)
                        {
                            // Most observed records for this family also carry a 32-bit spec word with hi16 == 0x0700.
                            // Treat any other hi16 as suspicious and don't decode.
                            if (!hasSpecU32 || unchecked((_specU32 >> 16) & 0xFFFF) == 0x0700)
                            {
                                var objIdx = (int)(unchecked(_specU16 & 0x00FF));
                                if (objIdx >= 1 && objIdx <= objects.Count)
                                {
                                    var off = (uint)_specU16b;

                                    // If the offset looks implausible, try a byte-swap (but only when it becomes plausible).
                                    var sz = ObjSize(objects, objIdx);
                                    if (sz != 0 && off > sz + 0x1000)
                                    {
                                        var swappedOff = (uint)(ushort)((_specU16b >> 8) | (_specU16b << 8));
                                        if (swappedOff <= sz + 0x1000)
                                            off = swappedOff;
                                    }

                                    if (sz == 0 || off <= sz + 0x1000)
                                    {
                                        targetKind = "internal";
                                        targetObj = objIdx;
                                        targetOff = off;
                                        var baseAddr = ObjBase(objects, objIdx);
                                        if (baseAddr != 0)
                                            targetLinear = unchecked(baseAddr + off);
                                    }
                                }
                            }
                        }

                        // Observed DOS4GW family: the low byte of specU16 mirrors the record type, specU16b encodes an
                        // explicit object index in its high byte (and a small sub-type/flags byte in its low byte), and
                        // specU32 packs (lo16 == specU16b) and (hi16 == object-relative offset).
                        // Decode only when these internal consistency checks pass.
                        if (targetKind == "unknown" && srcType == 0x10 && flags == 0x05 && hasSpecU32)
                        {
                            if (unchecked((byte)(_specU16 & 0x00FF)) == srcType)
                            {
                                var objIdx = (int)(unchecked((_specU16b >> 8) & 0x00FF));
                                var sub = (byte)unchecked(_specU16b & 0x00FF);
                                if (sub <= 0x0F && objIdx >= 1 && objIdx <= objects.Count)
                                {
                                    if (unchecked((ushort)(_specU32 & 0xFFFF)) == _specU16b)
                                    {
                                        var off = (uint)unchecked((_specU32 >> 16) & 0xFFFF);
                                        var sz = ObjSize(objects, objIdx);
                                        if (sz == 0 || off <= sz + 0x1000)
                                        {
                                            targetKind = "internal";
                                            targetObj = objIdx;
                                            targetOff = off;
                                            var baseAddr = ObjBase(objects, objIdx);
                                            if (baseAddr != 0)
                                                targetLinear = unchecked(baseAddr + off);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Some DOS4GW fixup record families appear to encode an explicit object index in the high byte of specU16,
                    // and an object-relative offset in specU32 (when present). We only decode when:
                    // - objIdx is explicit and in-range
                    // - specU16 low byte looks like a small sub-type (<= 0x0F)
                    // - when specU32 is present, its low16 matches specU16b (possibly with a byte swap)
                    // - offsets are plausible vs object size (+slack)
                    if (targetKind == "unknown" && hasSpecU16 && hasSpecU16b)
                    {
                        var objIdx = (int)(unchecked((_specU16 >> 8) & 0x00FF));
                        var sub = (byte)unchecked(_specU16 & 0x00FF);
                        if (sub <= 0x0F && objIdx >= 1 && objIdx <= objects.Count)
                        {
                            var allowNoSpecU32 = (srcType == 0x00 && flags == 0x07);
                            var canDecode = hasSpecU32 || allowNoSpecU32;
                            if (canDecode)
                            {
                                uint off;

                                if (hasSpecU32)
                                {
                                    var lo = (ushort)unchecked(_specU32 & 0xFFFF);
                                    if (lo != _specU16b)
                                    {
                                        var swappedLo = (ushort)((lo >> 8) | (lo << 8));
                                        if (swappedLo != _specU16b)
                                            goto SkipHiByteObjIdxDecode;
                                    }
                                    off = _specU32;
                                }
                                else
                                {
                                    off = _specU16b;
                                }

                                var sz = ObjSize(objects, objIdx);
                                if (sz != 0 && off > sz + 0x1000)
                                {
                                    // For the no-specU32 variant, try a byte swap only when it becomes plausible.
                                    if (!hasSpecU32)
                                    {
                                        var swappedOff = (uint)(ushort)((_specU16b >> 8) | (_specU16b << 8));
                                        if (swappedOff <= sz + 0x1000)
                                            off = swappedOff;
                                    }
                                }

                                if (sz == 0 || off <= sz + 0x1000)
                                {
                                    targetKind = "internal";
                                    targetObj = objIdx;
                                    targetOff = off;
                                    var baseAddr = ObjBase(objects, objIdx);
                                    if (baseAddr != 0)
                                        targetLinear = unchecked(baseAddr + off);
                                }
                            }
                        }
                    }

                SkipHiByteObjIdxDecode:;

                    // Some DOS4GW fixup record families appear to carry a byte-swapped 16-bit object-relative offset
                    // in specU16 and a tagged u16 in specU16b. For a small remaining bucket we can classify safely
                    // when type/flags match and the inferred offset maps uniquely into exactly one object.
                    if (targetKind == "unknown" && hasSpecU16 && hasSpecU16b)
                    {
                        if (srcType == 0x07 && flags == 0x00)
                        {
                            // Observed: specU16b has high byte 0x07 for this family (e.g., 0x0700/0x0702/0x0703).
                            if (unchecked((_specU16b & 0xFF00)) == 0x0700)
                            {
                                var off16 = (uint)(ushort)((_specU16 >> 8) | (_specU16 << 8));
                                if (off16 != 0 && TryMapOffsetToUniqueObject(objects, off16, out var tobj, out var tlin))
                                {
                                    targetKind = "internal";
                                    targetObj = tobj;
                                    targetOff = off16;
                                    targetLinear = tlin;
                                }
                            }
                        }

                        // Observed: some 8-byte records encode the target object index in specU16b with high bits set,
                        // and the target object-relative offset in specU16. Decode only when the object index is explicit
                        // and in-range.
                        if (targetKind == "unknown" && !hasSpecU32 && srcType == 0x40 && flags == 0x09)
                        {
                            // Treat 0xC000 as a tag and the low 14 bits as an object index.
                            if (unchecked((_specU16b & 0xC000)) == 0xC000)
                            {
                                var objIdx = (int)(unchecked(_specU16b & 0x3FFF));
                                if (objIdx >= 1 && objIdx <= objects.Count)
                                {
                                    var off = (uint)_specU16;
                                    var sz = ObjSize(objects, objIdx);
                                    if (sz == 0 || off <= sz + 0x1000)
                                    {
                                        targetKind = "internal";
                                        targetObj = objIdx;
                                        targetOff = off;
                                        var baseAddr = ObjBase(objects, objIdx);
                                        if (baseAddr != 0)
                                            targetLinear = unchecked(baseAddr + off);
                                    }
                                }
                            }
                        }
                    }


                    // Read addend / site value near fixup site.
                    var objOffset = (int)((uint)i * header.PageSize + srcOff);
                    uint? siteV32 = null;
                    ushort? siteV16 = null;
                    var chosenDelta = 0;

                    if (objOffset >= 0)
                    {
                        // Some DOS4GW/MS-DOS workflows store object-relative offsets (often 16-bit) at the fixup site,
                        // rather than a fully relocated linear address. If the offset fits uniquely into one object,
                        // we can classify the target safely even when the on-disk value is 0 or doesn't map as linear.
                        if (targetKind == "unknown")
                        {
                            for (var delta = -4; delta <= 8; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0)
                                    continue;

                                // Prefer u32 offsets first (matches typical disp32/imm32 fields), but keep it conservative.
                                if (off + 4 <= objBytes.Length)
                                {
                                    var v = ReadUInt32(objBytes, off);
                                    if (v != 0 && v <= 0xFFFF && TryMapOffsetToUniqueObject(objects, v, out var tobj, out var tlin))
                                    {
                                        siteV32 = v;
                                        chosenDelta = delta;
                                        targetKind = "internal";
                                        targetObj = tobj;
                                        targetOff = v;
                                        targetLinear = tlin;
                                        break;
                                    }
                                }

                                // Also try u16 offsets (common for selector/offset fixups).
                                if (!siteV32.HasValue && off + 2 <= objBytes.Length)
                                {
                                    var v16 = ReadUInt16(objBytes, off);
                                    if (v16 != 0 && v16 <= 0xFFFF && TryMapOffsetToUniqueObject(objects, v16, out var tobj, out var tlin))
                                    {
                                        siteV16 = v16;
                                        chosenDelta = delta;
                                        targetKind = "internal";
                                        targetObj = tobj;
                                        targetOff = v16;
                                        targetLinear = tlin;
                                        break;
                                    }
                                }
                            }
                        }

                        // Prefer a value that matches the target spec (internal pointers).
                        if (targetKind == "internal" && targetLinear.HasValue)
                        {
                            for (var delta = -4; delta <= 8; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0 || off + 4 > objBytes.Length)
                                    continue;
                                var v = ReadUInt32(objBytes, off);
                                // Accept if it lands in the same object and the addend is sane.
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff) && tobj == targetObj)
                                {
                                    var add = unchecked((long)toff - (long)targetOff.GetValueOrDefault());
                                    if (Math.Abs(add) <= 0x10000)
                                    {
                                        siteV32 = v;
                                        chosenDelta = delta;
                                        break;
                                    }
                                }
                                if (v == targetLinear.Value)
                                {
                                    siteV32 = v;
                                    chosenDelta = delta;
                                    break;
                                }
                            }
                        }

                        // If no match, try any mapped pointer near the site.
                        if (!siteV32.HasValue)
                        {
                            for (var delta = -4; delta <= 8; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0 || off + 4 > objBytes.Length)
                                    continue;
                                var v = ReadUInt32(objBytes, off);
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff))
                                {
                                    siteV32 = v;
                                    chosenDelta = delta;
                                    if (targetKind == "unknown")
                                    {
                                        targetKind = "internal";
                                        targetObj = tobj;
                                        targetOff = toff;
                                        targetLinear = v;
                                    }
                                    break;
                                }
                            }
                        }

                        // Fallback raw reads.
                        if (!siteV32.HasValue)
                        {
                            if (objOffset + 4 <= objBytes.Length)
                                siteV32 = ReadUInt32(objBytes, objOffset);
                            else if (objOffset + 2 <= objBytes.Length)
                                siteV16 = ReadUInt16(objBytes, objOffset);
                        }

                        // Some DOS4GW fixup families appear to represent a 16:16 far pointer payload (offset16:selector16)
                        // rather than a linear (LE object) target. We keep this strictly scoped and avoid guessing an
                        // internal object mapping.
                        //
                        // Heuristic contract (conservative):
                        // - type/flags identify the family
                        // - specU32 exists (record length >= 10)
                        // - the fixup site currently contains a 0 placeholder (common for loader-filled far pointers)
                        // - interpret specU32.hi16 as offset16 and specU16b as selector16
                        if (targetKind == "unknown" && srcType == 0x05 && flags == 0x00 && hasSpecU32 && hasSpecU16b && siteV32.HasValue && siteV32.Value == 0)
                        {
                            var off16 = (ushort)unchecked((_specU32 >> 16) & 0xFFFF);
                            var sel16 = _specU16b;

                            // Require at least one of the two words to be non-zero to avoid classifying pure zeros.
                            if (off16 != 0 || sel16 != 0)
                            {
                                targetKind = "far";
                                // Pack as selector:offset (hi16:lo16) for stable diffing; targetLinear/targetObject remain null.
                                targetOff = unchecked(((uint)sel16 << 16) | (uint)off16);
                            }
                        }

                        // Another observed DOS4GW family appears to pack a 16:16 payload directly in specU32, with
                        // lo16 == specU16b (selector) and hi16 == offset. Keep this strictly scoped and only classify
                        // when we also see a 0 placeholder at the fixup site.
                        if (targetKind == "unknown" && srcType == 0x09 && flags == 0x01 && hasSpecU32 && hasSpecU16b && siteV32.HasValue && siteV32.Value == 0)
                        {
                            // Require internal consistency: lo16(specU32) mirrors specU16b.
                            if (unchecked((ushort)(_specU32 & 0xFFFF)) == _specU16b)
                            {
                                var off16 = (ushort)unchecked((_specU32 >> 16) & 0xFFFF);
                                var sel16 = _specU16b;

                                if (off16 != 0 || sel16 != 0)
                                {
                                    targetKind = "far";
                                    targetOff = unchecked(((uint)sel16 << 16) | (uint)off16);
                                }
                            }
                        }

                        // Some remaining DOS4GW records (often 8-byte stride) appear to encode a 16-bit object-relative
                        // target offset in specU16/specU16b (sometimes byte-swapped), while the site value is 0.
                        // Decode only when there is exactly one unambiguous (field,endian) candidate that maps strictly
                        // to exactly one object.
                        if (targetKind == "unknown" && !hasSpecU32 && siteV32.HasValue && siteV32.Value == 0 && (hasSpecU16 || hasSpecU16b))
                        {
                            var seen = new HashSet<uint>();
                            var mapped = new List<(int obj, uint off, uint lin)>();

                            void ConsiderU16(ushort v)
                            {
                                var a = (uint)v;
                                if (a != 0)
                                    seen.Add(a);
                                var s = (uint)Swap16(v);
                                if (s != 0)
                                    seen.Add(s);
                            }

                            if (hasSpecU16)
                                ConsiderU16(_specU16);
                            if (hasSpecU16b)
                                ConsiderU16(_specU16b);

                            foreach (var cand in seen)
                            {
                                if (TryMapOffsetToSingleObjectStrict(objects, cand, out var tobj, out var tlin))
                                    mapped.Add((tobj, cand, tlin));
                            }

                            if (mapped.Count == 1)
                            {
                                targetKind = "internal";
                                targetObj = mapped[0].obj;
                                targetOff = mapped[0].off;
                                targetLinear = mapped[0].lin;
                            }
                        }
                    }

                    var addend32 = (int?)null;
                    if (targetKind == "internal" && siteV32.HasValue && targetLinear.HasValue)
                    {
                        // Only compute addends when the site value looks like a relocated linear address.
                        // When we classified via object-relative offsets (v <= 0xFFFF), the subtraction is not meaningful.
                        if (siteV32.Value > 0xFFFF)
                        {
                            var add = unchecked((long)siteV32.Value - (long)targetLinear.Value);
                            if (add >= int.MinValue && add <= int.MaxValue)
                                addend32 = (int)add;
                        }
                    }

                    byte[] recordBytes = null;
                    {
                        var n = Math.Max(0, Math.Min(16, recBound - p));
                        if (n > 0)
                        {
                            recordBytes = new byte[n];
                            Buffer.BlockCopy(fixupRecordStream, p, recordBytes, 0, n);
                        }
                    }

                    var siteLinear = unchecked(sourceLinear + (uint)chosenDelta);
                    fixups.Add(new LeFixupRecordInfo
                    {
                        siteLinear = siteLinear,
                        sourceLinear = sourceLinear,
                        siteDelta = (sbyte)Math.Min(sbyte.MaxValue, Math.Max(sbyte.MinValue, chosenDelta)),
                        sourceOffsetInPage = srcOff,
                        logicalPageNumber = logicalPageNumber1,
                        physicalPageNumber = physicalPage,
                        type = srcType,
                        flags = flags,
                        recordStreamOffset = p,
                        stride = stride,
                        recordBytes = recordBytes,
                        specU16 = hasSpecU16 ? _specU16 : (ushort?)null,
                        specU16b = hasSpecU16b ? _specU16b : (ushort?)null,
                        specU32 = hasSpecU32 ? _specU32 : (uint?)null,
                        siteValue32 = siteV32,
                        siteValue16 = siteV16,
                        targetKind = targetKind,
                        targetObject = targetObj,
                        targetOffset = targetOff,
                        targetLinear = targetLinear,
                        addend32 = addend32,
                        importModuleIndex = importModIdx,
                        importModule = importModName,
                        importProcNameOffset = importProcNameOff,
                        importProc = importProcName
                    });
                }
            }

            return fixups;
        }

        private static LeFixupChainInfo[] BuildFixupChains(List<LeFixupRecordInfo> fixups, List<string> importModules)
        {
            if (fixups == null || fixups.Count == 0)
                return Array.Empty<LeFixupChainInfo>();

            var groups = fixups
                .GroupBy(f => new
                {
                    k = f.targetKind ?? "unknown",
                    obj = f.targetObject,
                    off = f.targetOffset,
                    lin = f.targetLinear,
                    imod = f.importModuleIndex,
                    iproc = f.importProcNameOffset
                })
                .Select(g => new LeFixupChainInfo
                {
                    targetKind = g.Key.k,
                    targetObject = g.Key.obj,
                    targetOffset = g.Key.off,
                    targetLinear = g.Key.lin,
                    importModuleIndex = g.Key.imod,
                    importProcNameOffset = g.Key.iproc,
                    count = g.Count()
                })
                .OrderByDescending(c => c.count)
                .ThenBy(c => c.targetKind)
                .ThenBy(c => c.targetObject ?? 0)
                .ThenBy(c => c.targetOffset ?? 0)
                .ThenBy(c => c.importModuleIndex ?? 0)
                .ThenBy(c => c.importProcNameOffset ?? 0)
                .ToArray();

            // Keep output manageable.
            const int maxChains = 200;
            if (groups.Length > maxChains)
                groups = groups.Take(maxChains).ToArray();

            // Enrich import module names if available.
            if (importModules != null && importModules.Count > 0)
            {
                foreach (var c in groups)
                {
                    if (c.targetKind != "import")
                        continue;
                    if (c.importModuleIndex.HasValue && c.importModuleIndex.Value >= 1 && c.importModuleIndex.Value <= importModules.Count)
                    {
                        // Names live on per-fixup entries too; this is just best-effort context.
                    }
                }
            }

            return groups;
        }
    }
}
