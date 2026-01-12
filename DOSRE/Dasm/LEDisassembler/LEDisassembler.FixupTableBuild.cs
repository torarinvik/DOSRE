using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        public static bool TryBuildFixupTable(string inputFile, bool leScanMzOverlayFallback, out LeFixupTableInfo table, out string error)
        {
            table = null;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(inputFile) || !File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

            try
            {
                var fileBytes = File.ReadAllBytes(inputFile);
                if (!TryFindLEHeaderOffset(fileBytes, allowMzOverlayScanFallback: leScanMzOverlayFallback, out var leHeaderOffset))
                {
                    error = "LE header not found";
                    return false;
                }

                if (!TryParseHeader(fileBytes, leHeaderOffset, out var header, out error))
                    return false;

                var objects = ParseObjects(fileBytes, header);
                var pageMap = ParseObjectPageMap(fileBytes, header);
                var entryLinearU = ComputeEntryLinear(header, objects);
                var entryLinear = unchecked((uint)entryLinearU);

                var importModules = TryParseImportModules(fileBytes, header) ?? new List<string>();
                TryGetFixupStreams(fileBytes, header, out var fixupPageOffsets, out var fixupRecordStream);

                // Still return a payload even if there are no fixups; it makes automation easier.
                if (fixupPageOffsets == null || fixupRecordStream == null)
                {
                    table = new LeFixupTableInfo
                    {
                        inputFile = inputFile,
                        entryLinear = entryLinear,
                        pageSize = header.PageSize,
                        numberOfPages = header.NumberOfPages,
                        objects = objects.Select(o => new LeObjectInfo
                        {
                            index = o.Index,
                            virtualSize = o.VirtualSize,
                            baseAddress = o.BaseAddress,
                            flags = o.Flags,
                            pageMapIndex = o.PageMapIndex,
                            pageCount = o.PageCount
                        }).ToArray(),
                        importModules = importModules.Count > 0 ? importModules.ToArray() : null,
                        fixups = Array.Empty<LeFixupRecordInfo>(),
                        chains = Array.Empty<LeFixupChainInfo>()
                    };
                    return true;
                }

                var dataPagesBase = header.HeaderOffset + (int)header.DataPagesOffset;
                if (dataPagesBase <= 0 || dataPagesBase >= fileBytes.Length)
                {
                    error = "Invalid LE data pages offset";
                    return false;
                }

                // Reconstruct object bytes (needed to read addends/site values deterministically).
                var objBytesByIndex = new Dictionary<int, byte[]>();
                foreach (var o in objects)
                {
                    if (o.VirtualSize == 0 || o.PageCount == 0)
                        continue;
                    var bytes = ReconstructObjectBytes(fileBytes, header, pageMap, dataPagesBase, o);
                    if (bytes != null && bytes.Length > 0)
                        objBytesByIndex[o.Index] = bytes;
                }

                var allFixups = new List<LeFixupRecordInfo>();
                foreach (var obj in objects)
                {
                    if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes) || objBytes == null || objBytes.Length == 0)
                        continue;
                    allFixups.AddRange(ParseFixupTableForObject(header, objects, pageMap, importModules, fileBytes, fixupPageOffsets, fixupRecordStream, objBytes, obj));
                }

                // Deterministic ordering.
                allFixups = allFixups
                    .OrderBy(f => f.siteLinear)
                    .ThenBy(f => f.recordStreamOffset)
                    .ToList();

                // Improve accuracy: map each fixup site to a containing instruction start when possible.
                // This helps downstream exports attribute xrefs to the right function even when the fixup points into
                // the middle of an instruction (e.g., disp32/immediate bytes).
                if (allFixups.Count > 0)
                {
                    var fixupObjIndices = new HashSet<int>();
                    foreach (var f in allFixups)
                    {
                        var addr = f.siteLinear != 0 ? f.siteLinear : f.sourceLinear;
                        if (addr == 0)
                            continue;
                        if (TryMapLinearToObject(objects, addr, out var objIndex, out var _))
                            fixupObjIndices.Add(objIndex);
                    }

                    var decodedByObj = new Dictionary<int, (uint[] starts, ushort[] lens)>();
                    foreach (var objIndex in fixupObjIndices)
                    {
                        var obj = objects.FirstOrDefault(o => o.Index == objIndex);
                        if (obj.Index == 0)
                            continue;

                        var isExecutable = (obj.Flags & 0x0004) != 0;
                        if (!isExecutable)
                            continue;

                        if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes) || objBytes == null || objBytes.Length == 0)
                            continue;

                        var maxLen = (int)Math.Min(obj.VirtualSize, (uint)objBytes.Length);
                        if (maxLen <= 0)
                            continue;

                        // Decode from object base for full coverage.
                        var code = new byte[maxLen];
                        Buffer.BlockCopy(objBytes, 0, code, 0, maxLen);

                        var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_32, obj.BaseAddress, true);
                        var ins = dis.Disassemble().ToList();
                        if (ins.Count == 0)
                            continue;

                        var starts = new uint[ins.Count];
                        var lens = new ushort[ins.Count];
                        for (var i = 0; i < ins.Count; i++)
                        {
                            starts[i] = (uint)ins[i].Offset;
                            lens[i] = (ushort)Math.Max(1, ins[i].Length);
                        }

                        decodedByObj[obj.Index] = (starts, lens);
                    }

                    static int LowerBound(uint[] arr, uint value)
                    {
                        if (arr == null || arr.Length == 0)
                            return 0;
                        var idx = Array.BinarySearch(arr, value);
                        return idx < 0 ? ~idx : idx;
                    }

                    foreach (var f in allFixups)
                    {
                        var addr = f.siteLinear != 0 ? f.siteLinear : f.sourceLinear;
                        if (addr == 0)
                            continue;

                        if (!TryMapLinearToObject(objects, addr, out var objIndex, out var _))
                            continue;
                        if (!decodedByObj.TryGetValue(objIndex, out var ranges))
                            continue;

                        var starts = ranges.starts;
                        var lens = ranges.lens;

                        // Find candidate instruction start <= addr.
                        var lb = LowerBound(starts, addr);
                        var i0 = lb;
                        if (i0 >= starts.Length || starts[i0] > addr)
                            i0 = i0 - 1;
                        if (i0 < 0)
                            continue;

                        // Validate containment; if not contained, try the previous instruction once.
                        for (var tries = 0; tries < 2 && i0 >= 0; tries++, i0--)
                        {
                            var s = starts[i0];
                            var e = unchecked(s + (uint)lens[i0]);
                            if (addr >= s && addr < e)
                            {
                                f.instructionLinear = s;
                                break;
                            }
                        }
                    }
                }

                var chains = BuildFixupChains(allFixups, importModules);

                table = new LeFixupTableInfo
                {
                    inputFile = inputFile,
                    entryLinear = entryLinear,
                    pageSize = header.PageSize,
                    numberOfPages = header.NumberOfPages,
                    objects = objects.Select(o => new LeObjectInfo
                    {
                        index = o.Index,
                        virtualSize = o.VirtualSize,
                        baseAddress = o.BaseAddress,
                        flags = o.Flags,
                        pageMapIndex = o.PageMapIndex,
                        pageCount = o.PageCount
                    }).ToArray(),
                    importModules = importModules.Count > 0 ? importModules.ToArray() : null,
                    fixups = allFixups.ToArray(),
                    chains = chains
                };

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }
    }
}
