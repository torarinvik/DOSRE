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

                var recStart = (int)fixupPageOffsets[pageIndex0];
                var recEnd = (int)fixupPageOffsets[pageIndex0 + 1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                foreach (var rec in ParseAllRecordsForPage(fixupRecordStream, recStart, recEnd))
                {
                    var srcType = rec.SourceType;
                    var flags = rec.TargetFlags;
                    
                    var allSourceOffsets = new List<ushort>();
                    allSourceOffsets.Add(rec.SourceOffset);
                    if (rec.SecondarySourceOffsets != null)
                        allSourceOffsets.AddRange(rec.SecondarySourceOffsets);

                    foreach (var srcOffRaw in allSourceOffsets)
                    {
                        var srcOff = srcOffRaw;
                        if (srcOff >= header.PageSize)
                        {
                            var swapped = (ushort)((srcOff >> 8) | (srcOff << 8));
                            if (swapped < header.PageSize)
                                srcOff = swapped;
                        }
                        var sourceLinear = unchecked(pageLinearBase + srcOff);

                        // If we have explicit internal target data in the record, use it.
                        int? recTargetObj = null;
                        uint? recTargetOff = null;
                        if (rec.TargetType == 0 || rec.TargetType == 3) // Internal / Internal Linkage
                        {
                            recTargetObj = (int)rec.TargetObject;
                            recTargetOff = rec.TargetOffset;
                        }

                        // Best-effort: read value at/near fixup site from reconstructed object bytes.
                        // Some DOS4GW records appear to point slightly before the relocated field; probing
                        // a few bytes forward greatly reduces false positives (e.g., reading opcode bytes).
                        var objOffset = (int)((uint)i * header.PageSize + srcOff);
                        uint? value32 = null;
                        ushort? value16 = null;
                        int chosenDelta = 0;
                        int? mappedObj = null;
                        uint mappedOff = 0;

                        if (objOffset >= 0 && objBytes != null)
                        {
                            // Prefer mapped in-module pointers. If we find one at a nearby delta (records can be off-by-a-few),
                            // treat that delta as the actual relocated field start.
                            var currentObjIsExecutable = (obj.Flags & 0x0004) != 0;

                            for (var delta = -3; delta <= 4; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0)
                                    continue;
                                if (off + 4 > objBytes.Length)
                                    continue;

                                var v = ReadLEUInt32(objBytes, off);
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff))
                                {
                                    // If the record has an explicit target object, prioritize matches to that object.
                                    if (recTargetObj.HasValue && tobj != recTargetObj.Value)
                                    {
                                        // But don't reject it yet if we don't find a better match.
                                    }

                                    if (currentObjIsExecutable)
                                    {
                                        var tgt = objects.FirstOrDefault(o => o.Index == (uint)tobj);
                                        var targetIsExecutable = tgt.Index != 0 && (tgt.Flags & 0x0004) != 0;
                                        if (targetIsExecutable)
                                            continue;
                                    }

                                    value32 = v;
                                    chosenDelta = delta;
                                    mappedObj = tobj;
                                    mappedOff = toff;

                                    // If this matches our record's explicit target, we're very confident.
                                    if (recTargetObj.HasValue && tobj == recTargetObj.Value)
                                        break;
                                }

                                // NEW: If the record gives us an explicit target and offset, check if the site value
                                // matches that offset or is 0.
                                if (recTargetObj.HasValue && recTargetOff.HasValue)
                                {
                                    if (v == recTargetOff.Value || (v == 0 && delta == 0))
                                    {
                                        value32 = v;
                                        chosenDelta = delta;
                                        mappedObj = recTargetObj;
                                        mappedOff = recTargetOff.Value;
                                        if (v == recTargetOff.Value) break; // Perfect match
                                    }
                                }
                            }

                            // If the record gave us an explicit target but we didn't find a mapped linear address at the site,
                            // and the site value is 0 or small, it's likely an additive fixup where the base is the record target.
                            if (!mappedObj.HasValue && recTargetObj.HasValue)
                            {
                                mappedObj = recTargetObj;
                                mappedOff = recTargetOff ?? 0;
                                // chosenDelta remains 0 unless we find a reason otherwise.
                            }

                            // If no mapped pointer found, read the raw dword/word at the original site.
                            if (!value32.HasValue)
                            {
                                if (objOffset + 4 <= objBytes.Length)
                                    value32 = ReadLEUInt32(objBytes, objOffset);
                                else if (objOffset + 2 <= objBytes.Length)
                                    value16 = ReadLEUInt16(objBytes, objOffset);

                                // Keep small object-relative offsets only when they come from the actual record site.
                                // Avoid scanning neighboring bytes for these, as it can accidentally interpret opcode/disp/imm overlap.
                                if (value32.HasValue && value32.Value >= 0x10000 && !recTargetObj.HasValue)
                                    value32 = null;
                            }
                        }

                        // Ensure we capture internal targets from the record even if we aren't probing site bytes (e.g. global symbols pass).
                        if (!mappedObj.HasValue && recTargetObj.HasValue)
                        {
                            mappedObj = recTargetObj;
                            mappedOff = recTargetOff ?? 0;
                        }

                        string importModule = null;
                        string importProc = null;
                        if (importModules != null && importModules.Count > 0 && (rec.TargetType == 1 || rec.TargetType == 2))
                        {
                            var modIdx = (int)rec.TargetObject;
                            if (modIdx > 0 && modIdx <= importModules.Count)
                            {
                                importModule = importModules[modIdx - 1];
                                if (rec.TargetType == 2) // Import by Name
                                {
                                    importProc = TryReadImportProcName(fileBytes, header, rec.TargetOffset);
                                }
                                else if (rec.TargetType == 1) // Import by Ordinal
                                {
                                    importProc = $"ord_{rec.TargetOffset}";
                                }

                                if (importModule != null && importModule.Equals(header.ModuleName, StringComparison.OrdinalIgnoreCase))
                                {
                                    importModule = "[SELF]";
                                }
                            }
                        }

                        // Only keep fixups within the current disassembly window.
                        if (sourceLinear >= startLinear && sourceLinear < endLinear)
                        {
                            // Only shift the site address if we actually found a mapped in-module pointer at a nearby delta.
                            // Otherwise, keep the original record site (more stable, avoids misattributing to opcode bytes).
                            var siteLinear = mappedObj.HasValue ? unchecked(sourceLinear + (uint)chosenDelta) : sourceLinear;
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
                                Flags = flags,
                                TargetType = rec.TargetType,
                                ImportModule = importModule,
                                ImportProc = importProc
                            });
                        }
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

                var recStart = (int)fixupPageOffsets[pageIndex0];
                var recEnd = (int)fixupPageOffsets[pageIndex0+1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                foreach (var rec in ParseAllRecordsForPage(fixupRecordStream, recStart, recEnd))
                {
                    var p = rec.RecordStreamOffset;
                    var stride = rec.RecordLength;
                    var recBound = p + stride;

                    var srcType = rec.SourceType;
                    var flags = rec.TargetFlags;
                    var srcOff = rec.SourceOffset;
                    if (srcOff >= header.PageSize)
                    {
                        var swapped = (ushort)((srcOff >> 8) | (srcOff << 8));
                        if (swapped < header.PageSize)
                            srcOff = swapped;
                    }
                    var sourceLinear = unchecked(pageLinearBase + srcOff);

                    // Map standard Target Data fields for backward compatibility with the Info struct.
                    ushort? _specU16 = null;
                    ushort? _specU16b = null;
                    uint? _specU32 = null;
                    if (stride >= 6) { _specU16 = (ushort)(fixupRecordStream[p + 4] | (fixupRecordStream[p + 5] << 8)); }
                    if (stride >= 8) { _specU16b = (ushort)(fixupRecordStream[p + 6] | (fixupRecordStream[p + 7] << 8)); }
                    if (stride >= 10) { _specU32 = ReadLEUInt32(fixupRecordStream, p + 6); }

                    string targetKind = "unknown";
                    int? targetObj = null;
                    uint? targetOff = null;
                    uint? targetLinear = null;
                    ushort? importModIdx = null;
                    string importModName = null;
                    uint? importProcNameOff = null;
                    string importProcName = null;

                    // Initialize from native record decode results.
                    if (rec.TargetType == 0 || rec.TargetType == 3) // Internal / Internal Linkage
                    {
                        targetKind = "internal";
                        targetObj = rec.TargetObject;
                        targetOff = rec.TargetOffset;
                        if (targetObj.HasValue && targetObj.Value >= 1 && targetObj.Value <= objects.Count)
                        {
                            var b = ObjBase(objects, targetObj.Value);
                            if (b != 0) targetLinear = unchecked(b + (targetOff ?? 0));
                        }
                    }
                    else if (rec.TargetType == 1 || rec.TargetType == 2) // Import
                    {
                        targetKind = "import";
                        importModIdx = rec.TargetObject;
                        if (importModIdx.HasValue && importModules != null && importModIdx.Value >= 1 && importModIdx.Value <= importModules.Count)
                        {
                            importModName = importModules[importModIdx.Value - 1];
                            targetOff = rec.TargetOffset;
                            if (rec.TargetType == 2) // Name
                            {
                                importProcNameOff = rec.TargetOffset;
                                importProcName = TryReadImportProcName(fileBytes, header, importProcNameOff.Value);
                            }
                        }
                    }

                    // (Optional) keep historical "additive" heuristics if we want, but native decode covers most now.
                    // For now, only proceed to site probing if we found a plausible target or want to guess.

                    // Read addend / site value near fixup site.
                    var objOffset = (int)((uint)i * header.PageSize + srcOff);
                    uint? siteV32 = null;
                    ushort? siteV16 = null;
                    var chosenDelta = 0;

                    if (objOffset >= 0)
                    {
                        // Heuristic: if target is unknown, try to find a pointer at the site.
                        if (targetKind == "unknown")
                        {
                            for (var delta = -4; delta <= 8; delta++)
                            {
                                var off = objOffset + delta;
                                if (off < 0 || off + 4 > objBytes.Length) continue;

                                var v = ReadLEUInt32(objBytes, off);
                                if (v != 0 && TryMapLinearToObject(objects, v, out var tobj, out var toff))
                                {
                                    siteV32 = v;
                                    chosenDelta = delta;
                                    targetKind = "internal";
                                    targetObj = tobj;
                                    targetOff = toff;
                                    targetLinear = v;
                                    break;
                                }
                            }
                        }

                        // Prefer a site value that matches the target.
                        if (targetKind == "internal" && targetLinear.HasValue)
                        {
                            for (var delta = -4; delta <= 8; delta++)
                             {
                                var off = objOffset + delta;
                                if (off < 0 || off + 4 > objBytes.Length) continue;
                                var v = ReadLEUInt32(objBytes, off);
                                if (TryMapLinearToObject(objects, v, out var tobj, out var toff) && tobj == targetObj)
                                {
                                    siteV32 = v;
                                    chosenDelta = delta;
                                    break;
                                }
                             }
                        }

                        // Fallback site reads.
                        if (!siteV32.HasValue)
                        {
                            if (objOffset + 4 <= objBytes.Length) siteV32 = ReadLEUInt32(objBytes, objOffset);
                            else if (objOffset + 2 <= objBytes.Length) siteV16 = ReadLEUInt16(objBytes, objOffset);
                        }
                    }

                    var addend32 = (int?)null;
                    if (targetKind == "internal" && siteV32.HasValue && targetLinear.HasValue)
                    {
                        if (siteV32.Value > 0xFFFF)
                        {
                            var add = unchecked((long)siteV32.Value - (long)targetLinear.Value);
                            if (add >= int.MinValue && add <= int.MaxValue) addend32 = (int)add;
                        }
                    }

                    byte[] recordBytes = null;
                    {
                        var n = Math.Max(0, Math.Min(32, recBound - p));
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
                        specU16 = _specU16,
                        specU16b = _specU16b,
                        specU32 = _specU32,
                        siteValue32 = siteV32,
                        siteValue16 = siteV16,
                        targetKind = targetKind,
                        targetObject = targetObj,
                        targetOffset = targetOff,
                        targetLinear = targetLinear,
                        addend32 = addend32,
                        importModuleIndex = (ushort?)importModIdx,
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
