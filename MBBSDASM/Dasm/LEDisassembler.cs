using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MBBSDASM.Logging;
using NLog;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace MBBSDASM.Dasm
{
    /// <summary>
    /// Minimal disassembler for DOS4GW Linear Executable (LE) format.
    ///
    /// This is intentionally "minimal" compared to the NE pipeline:
    /// - No relocation/fixup processing
    /// - No import/entry table analysis
    /// - No MBBS analysis
    /// - No string scanning
    ///
    /// It reconstructs object bytes from LE pages and disassembles executable objects as x86_32.
    /// </summary>
    public static class LEDisassembler
    {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));

        private const ushort LE_OBJECT_ENTRY_SIZE = 24;

        private sealed class LEFixup
        {
            public uint SourceLinear;
            public ushort SourceOffsetInPage;
            public uint PageNumber; // 1-based physical page
            public string Description = string.Empty;
        }

        private struct LEHeader
        {
            public int HeaderOffset;
            public uint ModuleFlags;
            public uint NumberOfPages;
            public uint EntryEipObject;
            public uint EntryEip;
            public uint EntryEspObject;
            public uint EntryEsp;
            public uint PageSize;
            public uint LastPageSize;
            public uint ObjectTableOffset;
            public uint ObjectCount;
            public uint ObjectPageMapOffset;
            public uint FixupPageTableOffset;
            public uint FixupRecordTableOffset;
            public uint ImportModuleTableOffset;
            public uint ImportModuleTableEntries;
            public uint ImportProcTableOffset;
            public uint DataPagesOffset;
        }

        private struct LEObject
        {
            public int Index;
            public uint VirtualSize;
            public uint BaseAddress;
            public uint Flags;
            public uint PageMapIndex; // 1-based
            public uint PageCount;
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, bool leFixups, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (!File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

            var fileBytes = File.ReadAllBytes(inputFile);
            if (!TryFindLEHeaderOffset(fileBytes, out var leHeaderOffset))
            {
                error = "LE header not found";
                return false;
            }

            if (!TryParseHeader(fileBytes, leHeaderOffset, out var header, out error))
                return false;

            var objects = ParseObjects(fileBytes, header);
            var pageMap = ParseObjectPageMap(fileBytes, header);

            List<string> importModules = null;
            byte[] fixupRecordStream = null;
            uint[] fixupPageOffsets = null;

            if (leFixups)
            {
                importModules = TryParseImportModules(fileBytes, header);
                TryGetFixupStreams(fileBytes, header, out fixupPageOffsets, out fixupRecordStream);
            }

            var dataPagesBase = header.HeaderOffset + (int)header.DataPagesOffset;
            if (dataPagesBase <= 0 || dataPagesBase >= fileBytes.Length)
            {
                error = "Invalid LE data pages offset";
                return false;
            }

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (LE / DOS4GW)");
            sb.AppendLine($"; PageSize: {header.PageSize}  LastPageSize: {header.LastPageSize}  Pages: {header.NumberOfPages}");
            sb.AppendLine($"; Entry: Obj {header.EntryEipObject} + 0x{header.EntryEip:X} (Linear 0x{ComputeEntryLinear(header, objects):X})");
            if (leFixups)
                sb.AppendLine($"; NOTE: LE fixup annotations enabled (best-effort)");
            else
                sb.AppendLine($"; NOTE: Minimal LE support (no fixups/import analysis)");
            sb.AppendLine($"; XREFS: derived from relative CALL/JMP/Jcc only");
            if (leFull)
                sb.AppendLine("; LE mode: FULL (disassemble from object start)");
            if (!leFull && leBytesLimit.HasValue)
                sb.AppendLine($"; LE mode: LIMIT {leBytesLimit.Value} bytes");
            sb.AppendLine(";");

            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0 || obj.PageCount == 0)
                    continue;

                // Heuristic: treat objects with the EXECUTABLE bit (0x0004) as code.
                // Some toolchains may set different flags; if this is wrong, we still allow disassembling.
                var isExecutable = (obj.Flags & 0x0004) != 0;

                var objBytes = ReconstructObjectBytes(fileBytes, header, pageMap, dataPagesBase, obj);
                if (objBytes == null || objBytes.Length == 0)
                    continue;

                // Trim to virtual size when possible
                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)objBytes.Length);
                if (maxLen <= 0)
                    continue;

                var startOffsetWithinObject = 0;
                if (!leFull)
                {
                    if (header.EntryEipObject == (uint)obj.Index && header.EntryEip < (uint)maxLen)
                    {
                        startOffsetWithinObject = (int)header.EntryEip;
                    }
                    else
                    {
                        // Heuristic: avoid producing huge runs of "add [eax], al" from zero-filled regions.
                        for (var i = 0; i < maxLen; i++)
                        {
                            if (objBytes[i] != 0)
                            {
                                startOffsetWithinObject = i;
                                break;
                            }
                        }
                    }
                }

                sb.AppendLine(";-------------------------------------------");
                sb.AppendLine($"; Object {obj.Index}  Base: 0x{obj.BaseAddress:X8}  Size: 0x{obj.VirtualSize:X}  Flags: 0x{obj.Flags:X8}  Pages: {obj.PageCount}  {(isExecutable ? "CODE" : "DATA?")}");
                sb.AppendLine($"; Disassembly start: +0x{startOffsetWithinObject:X} (Linear 0x{(obj.BaseAddress + (uint)startOffsetWithinObject):X8})");
                sb.AppendLine("; LINEAR_ADDR BYTES DISASSEMBLY");
                sb.AppendLine(";-------------------------------------------");

                if (!isExecutable)
                {
                    sb.AppendLine("; Skipping non-executable object (use -minimal later if you want raw dump support)");
                    sb.AppendLine();
                    continue;
                }

                var codeLen = maxLen - startOffsetWithinObject;
                if (!leFull && leBytesLimit.HasValue)
                    codeLen = Math.Min(codeLen, leBytesLimit.Value);
                if (codeLen <= 0)
                {
                    sb.AppendLine("; (No bytes to disassemble)");
                    sb.AppendLine();
                    continue;
                }

                var code = new byte[codeLen];
                Buffer.BlockCopy(objBytes, startOffsetWithinObject, code, 0, codeLen);

                var startLinear = obj.BaseAddress + (uint)startOffsetWithinObject;
                var endLinear = startLinear + (uint)codeLen;

                List<LEFixup> objFixups = null;
                if (leFixups && fixupRecordStream != null && fixupPageOffsets != null)
                {
                    objFixups = ParseFixupsForWindow(
                        header,
                        objects,
                        pageMap,
                        importModules,
                        fileBytes,
                        fixupPageOffsets,
                        fixupRecordStream,
                        obj,
                        startLinear,
                        endLinear);
                }

                // First pass: disassemble and collect basic xrefs and function/label targets.
                var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_32, startLinear, true);
                var instructions = dis.Disassemble().ToList();

                var functionStarts = new HashSet<uint>();
                var labelTargets = new HashSet<uint>();
                var callXrefs = new Dictionary<uint, List<uint>>();
                var jumpXrefs = new Dictionary<uint, List<uint>>();

                if (header.EntryEipObject == (uint)obj.Index)
                {
                    var entryLinear = obj.BaseAddress + header.EntryEip;
                    if (entryLinear >= startLinear && entryLinear < endLinear)
                        functionStarts.Add(entryLinear);
                }

                foreach (var ins in instructions)
                {
                    if (TryGetRelativeBranchTarget(ins, out var target, out var isCall))
                    {
                        if (target >= startLinear && target < endLinear)
                        {
                            if (isCall)
                            {
                                functionStarts.Add(target);
                                if (!callXrefs.TryGetValue(target, out var callers))
                                    callXrefs[target] = callers = new List<uint>();
                                callers.Add((uint)ins.Offset);
                            }
                            else
                            {
                                labelTargets.Add(target);
                                if (!jumpXrefs.TryGetValue(target, out var sources))
                                    jumpXrefs[target] = sources = new List<uint>();
                                sources.Add((uint)ins.Offset);
                            }
                        }
                    }
                }

                // Second pass: render with labels and inline xref hints.
                var sortedFixups = objFixups == null ? null : objFixups.OrderBy(f => f.SourceLinear).ToList();
                var fixupIdx = 0;
                foreach (var ins in instructions)
                {
                    var addr = (uint)ins.Offset;

                    if (functionStarts.Contains(addr))
                    {
                        sb.AppendLine();
                        sb.AppendLine($"func_{addr:X8}:");
                        if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                            sb.AppendLine($"; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}");
                    }
                    else if (labelTargets.Contains(addr))
                    {
                        sb.AppendLine($"loc_{addr:X8}:");
                        if (jumpXrefs.TryGetValue(addr, out var sources) && sources.Count > 0)
                            sb.AppendLine($"; XREF: jumped from {string.Join(", ", sources.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}");
                    }

                    var bytes = BitConverter.ToString(ins.Bytes).Replace("-", string.Empty);
                    var line = $"{ins.Offset:X8}h {bytes.PadRight(Constants.MAX_INSTRUCTION_LENGTH, ' ')} {ins}";

                    if (TryGetRelativeBranchTarget(ins, out var branchTarget, out var isCall2))
                    {
                        var label = isCall2 ? $"func_{branchTarget:X8}" : $"loc_{branchTarget:X8}";
                        line += $" ; {(isCall2 ? "call" : "jmp")} {label}";
                    }

                    if (sortedFixups != null && sortedFixups.Count > 0)
                    {
                        var insStart = (uint)ins.Offset;
                        var insEnd = unchecked((uint)(insStart + (uint)ins.Length));
                        var fixupText = BuildFixupAnnotation(sortedFixups, insStart, insEnd, ref fixupIdx);
                        if (!string.IsNullOrEmpty(fixupText))
                            line += $" ; FIXUP: {fixupText}";
                    }

                    sb.AppendLine(line);
                }

                sb.AppendLine();
            }

            output = sb.ToString();
            return true;
        }

        private static string BuildFixupAnnotation(List<LEFixup> fixups, uint insStart, uint insEnd, ref int idx)
        {
            if (fixups == null || fixups.Count == 0)
                return string.Empty;

            // Advance past fixups that are below this instruction.
            while (idx < fixups.Count && fixups[idx].SourceLinear < insStart)
                idx++;

            if (idx >= fixups.Count)
                return string.Empty;

            var hit = new List<string>();
            var scan = idx;
            while (scan < fixups.Count)
            {
                var f = fixups[scan];
                if (f.SourceLinear >= insEnd)
                    break;
                hit.Add(f.Description);
                scan++;
            }

            if (hit.Count == 0)
                return string.Empty;

            // Cap spammy cases (some pages can have many fixups that land within a single instruction range).
            var distinct = hit.Distinct().ToList();
            const int maxShown = 3;
            if (distinct.Count <= maxShown)
                return string.Join(" | ", distinct);

            return string.Join(" | ", distinct.Take(maxShown)) + $" | (+{distinct.Count - maxShown} more)";
        }

        private static ulong ComputeEntryLinear(LEHeader header, List<LEObject> objects)
        {
            if (header.EntryEipObject == 0)
                return 0;

            var obj = objects.Find(o => o.Index == header.EntryEipObject);
            return obj.BaseAddress + header.EntryEip;
        }

        private static bool TryFindLEHeaderOffset(byte[] fileBytes, out int offset)
        {
            // Prefer the canonical LE signature + byte/word order fields.
            // For DOS4GW-produced LEs this tends to be unique.
            for (var i = 0; i <= fileBytes.Length - 4; i++)
            {
                if (fileBytes[i] == (byte)'L' && fileBytes[i + 1] == (byte)'E' && fileBytes[i + 2] == 0x00 &&
                    fileBytes[i + 3] == 0x00)
                {
                    offset = i;
                    return true;
                }
            }

            offset = 0;
            return false;
        }

        private static bool TryParseHeader(byte[] fileBytes, int headerOffset, out LEHeader header, out string error)
        {
            header = default;
            error = string.Empty;

            if (headerOffset < 0 || headerOffset + 0x84 >= fileBytes.Length)
            {
                error = "Invalid LE header offset";
                return false;
            }

            if (fileBytes[headerOffset] != (byte)'L' || fileBytes[headerOffset + 1] != (byte)'E')
            {
                error = "Invalid LE signature";
                return false;
            }

            // byte order + word order are 0 for little endian
            var byteOrder = ReadUInt16(fileBytes, headerOffset + 0x02);
            var wordOrder = ReadUInt16(fileBytes, headerOffset + 0x04);
            if (byteOrder != 0 || wordOrder != 0)
            {
                error = "Unsupported LE byte/word order";
                return false;
            }

            header.HeaderOffset = headerOffset;

            header.ModuleFlags = ReadUInt32(fileBytes, headerOffset + 0x10);
            header.NumberOfPages = ReadUInt32(fileBytes, headerOffset + 0x14);
            header.EntryEipObject = ReadUInt32(fileBytes, headerOffset + 0x18);
            header.EntryEip = ReadUInt32(fileBytes, headerOffset + 0x1C);
            header.EntryEspObject = ReadUInt32(fileBytes, headerOffset + 0x20);
            header.EntryEsp = ReadUInt32(fileBytes, headerOffset + 0x24);
            header.PageSize = ReadUInt32(fileBytes, headerOffset + 0x28);
            header.LastPageSize = ReadUInt32(fileBytes, headerOffset + 0x2C);

            header.ObjectTableOffset = ReadUInt32(fileBytes, headerOffset + 0x40);
            header.ObjectCount = ReadUInt32(fileBytes, headerOffset + 0x44);
            header.ObjectPageMapOffset = ReadUInt32(fileBytes, headerOffset + 0x48);

            header.FixupPageTableOffset = ReadUInt32(fileBytes, headerOffset + 0x68);
            header.FixupRecordTableOffset = ReadUInt32(fileBytes, headerOffset + 0x6C);

            // Best-effort: import tables (offsets are relative to LE header)
            header.ImportModuleTableOffset = ReadUInt32(fileBytes, headerOffset + 0x70);
            header.ImportModuleTableEntries = ReadUInt32(fileBytes, headerOffset + 0x74);
            header.ImportProcTableOffset = ReadUInt32(fileBytes, headerOffset + 0x78);

            header.DataPagesOffset = ReadUInt32(fileBytes, headerOffset + 0x80);

            if (header.PageSize == 0 || header.ObjectCount == 0 || header.NumberOfPages == 0)
            {
                error = "Invalid LE header (zero PageSize/ObjectCount/PageCount)";
                return false;
            }

            // If last page size is 0, treat it as full page size per spec conventions.
            if (header.LastPageSize == 0)
                header.LastPageSize = header.PageSize;

            _logger.Info($"Detected LE header at 0x{headerOffset:X} (Objects={header.ObjectCount}, Pages={header.NumberOfPages}, PageSize={header.PageSize})");
            return true;
        }

        private static List<string> TryParseImportModules(byte[] fileBytes, LEHeader header)
        {
            try
            {
                if (header.ImportModuleTableOffset == 0 || header.ImportModuleTableEntries == 0)
                    return null;

                var start = header.HeaderOffset + (int)header.ImportModuleTableOffset;
                if (start < 0 || start >= fileBytes.Length)
                    return null;

                var modules = new List<string>((int)Math.Min(header.ImportModuleTableEntries, 4096));
                var off = start;
                for (var i = 0; i < header.ImportModuleTableEntries; i++)
                {
                    if (off >= fileBytes.Length)
                        break;
                    var len = fileBytes[off];
                    off++;
                    if (len == 0)
                    {
                        modules.Add(string.Empty);
                        continue;
                    }
                    if (off + len > fileBytes.Length)
                        break;
                    var name = Encoding.ASCII.GetString(fileBytes, off, len);
                    modules.Add(name);
                    off += len;
                }

                return modules;
            }
            catch
            {
                return null;
            }
        }

        private static string TryReadImportProcName(byte[] fileBytes, LEHeader header, uint procNameOffset)
        {
            try
            {
                if (header.ImportProcTableOffset == 0)
                    return string.Empty;

                var baseOff = header.HeaderOffset + (int)header.ImportProcTableOffset;
                var off = baseOff + (int)procNameOffset;
                if (off < 0 || off >= fileBytes.Length)
                    return string.Empty;
                var len = fileBytes[off];
                off++;
                if (len == 0)
                    return string.Empty;
                if (off + len > fileBytes.Length)
                    return string.Empty;
                return Encoding.ASCII.GetString(fileBytes, off, len);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool TryGetFixupStreams(byte[] fileBytes, LEHeader header, out uint[] fixupPageOffsets, out byte[] fixupRecordStream)
        {
            fixupPageOffsets = null;
            fixupRecordStream = null;

            try
            {
                if (header.FixupPageTableOffset == 0 || header.FixupRecordTableOffset == 0 || header.NumberOfPages == 0)
                    return false;

                var pageTableStart = header.HeaderOffset + (int)header.FixupPageTableOffset;
                var recordStart = header.HeaderOffset + (int)header.FixupRecordTableOffset;
                if (pageTableStart < 0 || pageTableStart >= fileBytes.Length)
                    return false;
                if (recordStart < 0 || recordStart >= fileBytes.Length)
                    return false;

                var count = checked((int)header.NumberOfPages + 1);
                var offsets = new uint[count];
                for (var i = 0; i < count; i++)
                {
                    var off = pageTableStart + i * 4;
                    if (off + 4 > fileBytes.Length)
                        return false;
                    offsets[i] = ReadUInt32(fileBytes, off);
                }

                var total = offsets[count - 1];
                if (total == 0)
                    return false;
                if (recordStart + total > fileBytes.Length)
                    total = (uint)Math.Max(0, fileBytes.Length - recordStart);

                var records = new byte[total];
                Buffer.BlockCopy(fileBytes, recordStart, records, 0, (int)total);

                fixupPageOffsets = offsets;
                fixupRecordStream = records;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static List<LEFixup> ParseFixupsForWindow(
            LEHeader header,
            List<LEObject> objects,
            uint[] pageMap,
            List<string> importModules,
            byte[] fileBytes,
            uint[] fixupPageOffsets,
            byte[] fixupRecordStream,
            LEObject obj,
            uint startLinear,
            uint endLinear)
        {
            // Best-effort decoder for a subset of LE fixup records.
            // It’s deliberately defensive; if parsing goes off-rails for a page, we stop for that page.
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

                var recStart = fixupPageOffsets[pageIndex0];
                var recEnd = fixupPageOffsets[pageIndex0 + 1];
                if (recEnd <= recStart)
                    continue;
                if (recEnd > fixupRecordStream.Length)
                    continue;

                var p = (int)recStart;
                var limit = (int)recEnd;
                while (p + 4 <= limit)
                {
                    var srcType = fixupRecordStream[p++];
                    var flags = fixupRecordStream[p++];
                    var srcOff = (ushort)(fixupRecordStream[p] | (fixupRecordStream[p + 1] << 8));
                    p += 2;

                    var sourceLinear = unchecked(pageLinearBase + srcOff);

                    // The LE/LX fixup format is nuanced. We'll decode a small, validated subset.
                    // If validation fails, we fall back to a compact raw marker while still advancing.
                    string desc;

                    // Most fixup records we care about include at least 6 more bytes.
                    if (p + 6 > limit)
                        break;

                    var w1 = (ushort)(fixupRecordStream[p] | (fixupRecordStream[p + 1] << 8));
                    var d1 = ReadUInt32(fixupRecordStream, p + 2);

                    // Heuristic 1: internal object+offset
                    if (w1 >= 1 && w1 <= header.ObjectCount)
                    {
                        var targetObj = w1;
                        var targetOff = d1;
                        var objEntry = objects.FirstOrDefault(o => o.Index == targetObj);
                        // targetOff should usually be within virtual size when it points into object memory.
                        if (objEntry.VirtualSize == 0 || targetOff < objEntry.VirtualSize + header.PageSize)
                        {
                            var targetLinear = unchecked(objEntry.BaseAddress + targetOff);
                            desc = $"internal obj{targetObj}+0x{targetOff:X} (0x{targetLinear:X8})";
                        }
                        else
                        {
                            desc = $"fixup type=0x{srcType:X2} flags=0x{flags:X2}";
                        }
                    }
                    else
                    {
                        // Heuristic 2: import by name (module index + proc name offset)
                        var mod = w1;
                        var procOff = d1;
                        var modName = (importModules != null && mod > 0 && mod <= importModules.Count) ? importModules[mod - 1] : string.Empty;
                        var procName = !string.IsNullOrEmpty(modName) ? TryReadImportProcName(fileBytes, header, procOff) : string.Empty;
                        if (!string.IsNullOrEmpty(modName) && !string.IsNullOrEmpty(procName))
                        {
                            desc = $"import {modName}!{procName}";
                        }
                        else
                        {
                            // Heuristic 3: import by ordinal (module index + ordinal in low word of d1)
                            var ord = (ushort)(d1 & 0xFFFF);
                            if (!string.IsNullOrEmpty(modName) && ord != 0)
                                desc = $"import {modName}!#{ord}";
                            else
                                desc = $"fixup type=0x{srcType:X2} flags=0x{flags:X2}";
                        }
                    }

                    // Advance past the fields we just sampled.
                    p += 6;

                    // Best-effort: additive value present
                    if ((flags & 0x04) != 0)
                    {
                        if (p + 4 <= limit)
                            p += 4;
                    }

                    // Only keep fixups within the current disassembly window.
                    if (sourceLinear >= startLinear && sourceLinear < endLinear)
                    {
                        fixups.Add(new LEFixup
                        {
                            SourceLinear = sourceLinear,
                            SourceOffsetInPage = srcOff,
                            PageNumber = physicalPage,
                            Description = desc
                        });
                    }
                }
            }

            return fixups;
        }

        private static List<LEObject> ParseObjects(byte[] fileBytes, LEHeader header)
        {
            var objects = new List<LEObject>((int)header.ObjectCount);

            var objectTableStart = header.HeaderOffset + (int)header.ObjectTableOffset;
            for (var i = 0; i < header.ObjectCount; i++)
            {
                var entryOffset = objectTableStart + i * LE_OBJECT_ENTRY_SIZE;
                if (entryOffset + LE_OBJECT_ENTRY_SIZE > fileBytes.Length)
                    break;

                // LE object entry is 6x uint32
                var virtualSize = ReadUInt32(fileBytes, entryOffset + 0x00);
                var baseAddress = ReadUInt32(fileBytes, entryOffset + 0x04);
                var flags = ReadUInt32(fileBytes, entryOffset + 0x08);
                var pageMapIndex = ReadUInt32(fileBytes, entryOffset + 0x0C);
                var pageCount = ReadUInt32(fileBytes, entryOffset + 0x10);

                objects.Add(new LEObject
                {
                    Index = i + 1,
                    VirtualSize = virtualSize,
                    BaseAddress = baseAddress,
                    Flags = flags,
                    PageMapIndex = pageMapIndex,
                    PageCount = pageCount
                });
            }

            return objects;
        }

        private static uint[] ParseObjectPageMap(byte[] fileBytes, LEHeader header)
        {
            var pageMapStart = header.HeaderOffset + (int)header.ObjectPageMapOffset;
            var map = new uint[header.NumberOfPages];

            for (var i = 0; i < map.Length; i++)
            {
                var off = pageMapStart + i * 4;
                if (off + 4 > fileBytes.Length)
                    break;

                // LE object page map entries are 4 bytes.
                // For DOS4GW-style LEs, the physical page number is stored as a 16-bit value in the upper word.
                // (The lower word is typically flags.)
                map[i] = ReadUInt16(fileBytes, off + 2);
            }

            return map;
        }

        private static byte[] ReconstructObjectBytes(byte[] fileBytes, LEHeader header, uint[] pageMap, int dataPagesBase, LEObject obj)
        {
            var pageSize = (int)header.PageSize;
            var totalLen = checked((int)obj.PageCount * pageSize);
            var buf = new byte[totalLen];

            for (var i = 0; i < obj.PageCount; i++)
            {
                var pageMapIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (pageMapIndex0 < 0 || pageMapIndex0 >= pageMap.Length)
                    break;

                var physicalPage = pageMap[pageMapIndex0]; // 1-based
                if (physicalPage == 0)
                    continue;

                var isLastModulePage = physicalPage == header.NumberOfPages;
                var bytesThisPage = isLastModulePage ? (int)header.LastPageSize : pageSize;

                var pageFileOffset = dataPagesBase + (int)(physicalPage - 1) * pageSize;
                if (pageFileOffset < 0 || pageFileOffset >= fileBytes.Length)
                    break;

                var available = Math.Min(bytesThisPage, fileBytes.Length - pageFileOffset);
                if (available <= 0)
                    break;

                Buffer.BlockCopy(fileBytes, pageFileOffset, buf, i * pageSize, available);
            }

            return buf;
        }

        private static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)(data[offset] |
                          (data[offset + 1] << 8) |
                          (data[offset + 2] << 16) |
                          (data[offset + 3] << 24));
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
    }
}
