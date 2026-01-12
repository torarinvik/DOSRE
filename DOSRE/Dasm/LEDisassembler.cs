using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DOSRE.Analysis;
using DOSRE.Enums;
using DOSRE.Logging;
using NLog;
using SharpDisasm;
using SharpDisasm.Udis86;

namespace DOSRE.Dasm
{
    /// Minimal disassembler for DOS4GW Linear Executable (LE) format.
    ///
    /// This is intentionally "minimal" compared to the NE pipeline:
    /// - No relocation/fixup processing
    /// - No import/entry table analysis
    /// - No NE-specific analysis
    /// - No string scanning
    ///
    /// It reconstructs object bytes from LE pages and disassembles executable objects as x86_32.
    /// </summary>
    public static partial class LEDisassembler
    {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));

        public sealed class LeBasicBlockInfo
        {
            public uint Start { get; set; }
            public List<uint> Predecessors { get; set; } = new List<uint>();
            public List<uint> Successors { get; set; } = new List<uint>();
        }

        public sealed class LeFunctionCfg
        {
            public uint FunctionStart { get; set; }
            public Dictionary<uint, LeBasicBlockInfo> Blocks { get; } = new Dictionary<uint, LeBasicBlockInfo>();
        }

        public sealed class LeFunctionInfo
        {
            public uint Start { get; set; }
            public int InstructionCount { get; set; }
            public int BlockCount { get; set; }
            public List<uint> Calls { get; set; } = new List<uint>();
            public List<string> Globals { get; set; } = new List<string>();
            public List<string> Strings { get; set; } = new List<string>();
        }

        public sealed class LeAnalysis
        {
            public string InputFile { get; set; }
            public uint EntryLinear { get; set; }
            public Dictionary<uint, LeFunctionInfo> Functions { get; } = new Dictionary<uint, LeFunctionInfo>();
            public Dictionary<uint, LeFunctionCfg> CfgByFunction { get; } = new Dictionary<uint, LeFunctionCfg>();
        }

        public sealed class LeObjectInfo
        {
            public int index { get; set; }
            public uint virtualSize { get; set; }
            public uint baseAddress { get; set; }
            public uint flags { get; set; }
            public uint pageMapIndex { get; set; }
            public uint pageCount { get; set; }
        }

        public sealed class LeFixupRecordInfo
        {
            public uint siteLinear { get; set; }
            public uint sourceLinear { get; set; }
            public uint? instructionLinear { get; set; }
            public sbyte siteDelta { get; set; }
            public ushort sourceOffsetInPage { get; set; }
            public uint logicalPageNumber { get; set; }
            public uint physicalPageNumber { get; set; }

            public byte type { get; set; }
            public byte flags { get; set; }
            public int recordStreamOffset { get; set; }
            public int stride { get; set; }

            // Raw record bytes (best-effort, truncated to keep JSON manageable).
            public byte[] recordBytes { get; set; }

            // Best-effort parsed spec fields from within the record (never read across stride).
            public ushort? specU16 { get; set; }
            public ushort? specU16b { get; set; }
            public uint? specU32 { get; set; }

            public uint? siteValue32 { get; set; }
            public ushort? siteValue16 { get; set; }

            public string targetKind { get; set; } // "internal", "import", "far", "unknown"
            public int? targetObject { get; set; }
            public uint? targetOffset { get; set; }
            public uint? targetLinear { get; set; }
            public int? addend32 { get; set; }

            public ushort? importModuleIndex { get; set; }
            public string importModule { get; set; }
            public uint? importProcNameOffset { get; set; }
            public string importProc { get; set; }
        }

        public sealed class LeFixupChainInfo
        {
            public string targetKind { get; set; }
            public int? targetObject { get; set; }
            public uint? targetOffset { get; set; }
            public uint? targetLinear { get; set; }
            public ushort? importModuleIndex { get; set; }
            public uint? importProcNameOffset { get; set; }
            public int count { get; set; }
        }

        public sealed class LeFixupTableInfo
        {
            public string inputFile { get; set; }
            public uint entryLinear { get; set; }
            public uint pageSize { get; set; }
            public uint numberOfPages { get; set; }

            public LeObjectInfo[] objects { get; set; }
            public string[] importModules { get; set; }
            public LeFixupRecordInfo[] fixups { get; set; }
            public LeFixupChainInfo[] chains { get; set; }
        }

        public sealed class LeReachabilityRangeInfo
        {
            public uint startLinear { get; set; }
            public uint endLinear { get; set; }
        }

        public sealed class LeReachabilityObjectInfo
        {
            public int index { get; set; }
            public uint baseAddress { get; set; }
            public uint virtualSize { get; set; }
            public uint flags { get; set; }

            public uint decodedStartLinear { get; set; }
            public uint decodedEndLinear { get; set; }

            public int instructionCount { get; set; }
            public int reachableInstructionCount { get; set; }
            public int reachableByteCount { get; set; }

            public LeReachabilityRangeInfo[] reachableCodeRanges { get; set; }
            public LeReachabilityRangeInfo[] dataCandidateRanges { get; set; }
        }

        public sealed class LeReachabilityInfo
        {
            public string inputFile { get; set; }
            public uint entryLinear { get; set; }
            public LeReachabilityObjectInfo[] objects { get; set; }
        }

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

        public static bool TryBuildReachabilityMap(string inputFile, bool leScanMzOverlayFallback, out LeReachabilityInfo map, out string error)
        {
            map = null;
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

                var dataPagesBase = header.HeaderOffset + (int)header.DataPagesOffset;
                if (dataPagesBase <= 0 || dataPagesBase >= fileBytes.Length)
                {
                    error = "Invalid LE data pages offset";
                    return false;
                }

                var objBytesByIndex = new Dictionary<int, byte[]>();
                foreach (var o in objects)
                {
                    if (o.VirtualSize == 0 || o.PageCount == 0)
                        continue;
                    var bytes = ReconstructObjectBytes(fileBytes, header, pageMap, dataPagesBase, o);
                    if (bytes != null && bytes.Length > 0)
                        objBytesByIndex[o.Index] = bytes;
                }

                // Decode executable objects from the start (full coverage for reachability marking).
                var execObjIndices = new HashSet<int>();
                var execObjInstructions = new Dictionary<int, List<Instruction>>();
                var execObjInsIndexByAddr = new Dictionary<int, Dictionary<uint, int>>();
                var execObjStarts = new Dictionary<int, uint[]>();
                var execObjLens = new Dictionary<int, ushort[]>();
                var execObjDecodedEndLinear = new Dictionary<int, uint>();

                foreach (var obj in objects)
                {
                    if (obj.VirtualSize == 0 || obj.PageCount == 0)
                        continue;

                    var isExecutable = (obj.Flags & 0x0004) != 0;
                    if (!isExecutable)
                        continue;

                    if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes) || objBytes == null || objBytes.Length == 0)
                        continue;

                    var maxLen = (int)Math.Min(obj.VirtualSize, (uint)objBytes.Length);
                    if (maxLen <= 0)
                        continue;

                    var code = new byte[maxLen];
                    Buffer.BlockCopy(objBytes, 0, code, 0, maxLen);

                    var startLinear = obj.BaseAddress;
                    var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_32, startLinear, true);
                    var instructions = dis.Disassemble().ToList();
                    if (instructions.Count == 0)
                        continue;

                    var insIndexByAddr = new Dictionary<uint, int>(instructions.Count);
                    var starts = new uint[instructions.Count];
                    var lens = new ushort[instructions.Count];
                    for (var ii = 0; ii < instructions.Count; ii++)
                    {
                        var off = (uint)instructions[ii].Offset;
                        insIndexByAddr[off] = ii;
                        starts[ii] = off;
                        lens[ii] = (ushort)Math.Max(1, instructions[ii].Length);
                    }

                    execObjIndices.Add(obj.Index);
                    execObjInstructions[obj.Index] = instructions;
                    execObjInsIndexByAddr[obj.Index] = insIndexByAddr;
                    execObjStarts[obj.Index] = starts;
                    execObjLens[obj.Index] = lens;
                    execObjDecodedEndLinear[obj.Index] = unchecked(startLinear + (uint)maxLen);
                }

                static int LowerBound(uint[] arr, uint value)
                {
                    if (arr == null || arr.Length == 0)
                        return 0;
                    var idx = Array.BinarySearch(arr, value);
                    return idx < 0 ? ~idx : idx;
                }

                bool TryNormalizeToContainingInstruction(uint addr, out uint insStart)
                {
                    insStart = 0;
                    if (!TryMapLinearToObject(objects, addr, out var objIndex, out var _))
                        return false;
                    if (!execObjIndices.Contains(objIndex))
                        return false;
                    if (!execObjStarts.TryGetValue(objIndex, out var starts) || starts == null || starts.Length == 0)
                        return false;
                    if (!execObjLens.TryGetValue(objIndex, out var lens) || lens == null || lens.Length != starts.Length)
                        return false;

                    var lb = LowerBound(starts, addr);
                    var i0 = lb;
                    if (i0 >= starts.Length || starts[i0] > addr)
                        i0 = i0 - 1;
                    if (i0 < 0)
                        return false;

                    for (var tries = 0; tries < 2 && i0 >= 0; tries++, i0--)
                    {
                        var s = starts[i0];
                        var e = unchecked(s + (uint)lens[i0]);
                        if (addr >= s && addr < e)
                        {
                            insStart = s;
                            return true;
                        }
                    }

                    return false;
                }

                bool TryNormalizeToDecodedInstructionStart(uint addr, out uint insStart)
                {
                    insStart = 0;
                    if (!TryMapLinearToObject(objects, addr, out var objIndex, out var _))
                        return false;
                    if (!execObjIndices.Contains(objIndex))
                        return false;
                    if (!execObjInsIndexByAddr.TryGetValue(objIndex, out var idxByAddr) || idxByAddr == null)
                        return false;
                    if (!idxByAddr.ContainsKey(addr))
                        return false;
                    insStart = addr;
                    return true;
                }

                var visited = new HashSet<uint>();
                var queue = new Queue<uint>();

                // Seed: entry point (snap to containing instruction to avoid "mid-instruction" entry EIP).
                if (TryNormalizeToContainingInstruction(entryLinear, out var entryIns))
                {
                    visited.Add(entryIns);
                    queue.Enqueue(entryIns);
                }

                while (queue.Count > 0)
                {
                    var addr = queue.Dequeue();
                    if (!TryMapLinearToObject(objects, addr, out var objIndex, out var _))
                        continue;
                    if (!execObjIndices.Contains(objIndex))
                        continue;
                    if (!execObjInstructions.TryGetValue(objIndex, out var instructions) || instructions == null || instructions.Count == 0)
                        continue;
                    if (!execObjInsIndexByAddr.TryGetValue(objIndex, out var idxByAddr) || idxByAddr == null)
                        continue;
                    if (!idxByAddr.TryGetValue(addr, out var idx))
                        continue;

                    void EnqueueIfValid(uint target)
                    {
                        if (!TryNormalizeToDecodedInstructionStart(target, out var t))
                            return;
                        if (visited.Add(t))
                            queue.Enqueue(t);
                    }

                    var ins = instructions[idx];

                    // Default fallthrough.
                    uint? next = null;
                    if (idx + 1 < instructions.Count)
                        next = (uint)instructions[idx + 1].Offset;

                    if (TryGetRelativeBranchTarget(ins, out var target, out var isCall))
                    {
                        if (isCall)
                        {
                            EnqueueIfValid(target);
                            if (next.HasValue)
                                EnqueueIfValid(next.Value);
                        }
                        else
                        {
                            EnqueueIfValid(target);
                            if (IsConditionalBranch(ins) && next.HasValue)
                                EnqueueIfValid(next.Value);
                        }
                    }
                    else
                    {
                        // Try to follow jump-table targets for indirect jmps (best-effort).
                        if (idxByAddr.ContainsKey(addr))
                        {
                            var wantCases = 16;
                            if (TryParseIndirectJmpTable(ins.Bytes, out var _, out var idxRegProbe, out var scaleProbe))
                            {
                                if (TryInferJumpTableSwitchBound(instructions, idx, idxRegProbe, out var inferredCasesProbe, out var _))
                                    wantCases = Math.Min(64, Math.Max(1, inferredCasesProbe));
                            }

                            if (TryGetJumpTableTargets(instructions, idxByAddr, idx, ins, objects, objBytesByIndex, maxEntries: wantCases, out var _, out var idxReg, out var jtTargets))
                            {
                                var casesToAdd = jtTargets.Count;
                                if (TryInferJumpTableSwitchBound(instructions, idx, idxReg, out var inferredCases, out var _))
                                    casesToAdd = Math.Min(casesToAdd, Math.Max(1, inferredCases));
                                casesToAdd = Math.Min(casesToAdd, 32);

                                for (var ti = 0; ti < casesToAdd; ti++)
                                    EnqueueIfValid(jtTargets[ti]);
                            }
                        }

                        var t = InsText(ins);
                        if (t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                        {
                            // no fallthrough
                        }
                        else
                        {
                            if (next.HasValue)
                                EnqueueIfValid(next.Value);
                        }
                    }
                }

                // Build per-object ranges.
                var outObjects = new List<LeReachabilityObjectInfo>();
                foreach (var obj in objects.OrderBy(o => o.Index))
                {
                    var maxLen = 0;
                    if (objBytesByIndex.TryGetValue(obj.Index, out var bytes) && bytes != null)
                        maxLen = (int)Math.Min(obj.VirtualSize, (uint)bytes.Length);

                    if (!execObjIndices.Contains(obj.Index) || maxLen <= 0 || !execObjInstructions.TryGetValue(obj.Index, out var insList) || insList == null)
                    {
                        outObjects.Add(new LeReachabilityObjectInfo
                        {
                            index = obj.Index,
                            baseAddress = obj.BaseAddress,
                            virtualSize = obj.VirtualSize,
                            flags = obj.Flags,
                            decodedStartLinear = obj.BaseAddress,
                            decodedEndLinear = unchecked(obj.BaseAddress + (uint)Math.Max(0, maxLen)),
                            instructionCount = 0,
                            reachableInstructionCount = 0,
                            reachableByteCount = 0,
                            reachableCodeRanges = Array.Empty<LeReachabilityRangeInfo>(),
                            dataCandidateRanges = Array.Empty<LeReachabilityRangeInfo>(),
                        });
                        continue;
                    }

                    var covered = new bool[maxLen];
                    var reachableIns = 0;
                    var reachableBytes = 0;

                    foreach (var ins in insList)
                    {
                        var addr = (uint)ins.Offset;
                        if (!visited.Contains(addr))
                            continue;
                        reachableIns++;

                        var off = (int)(addr - obj.BaseAddress);
                        var len = Math.Max(1, ins.Length);
                        if (off < 0 || off >= maxLen)
                            continue;
                        var end = Math.Min(maxLen, off + len);
                        for (var i = off; i < end; i++)
                        {
                            if (!covered[i])
                            {
                                covered[i] = true;
                                reachableBytes++;
                            }
                        }
                    }

                    static LeReachabilityRangeInfo[] BuildRanges(bool[] mask, bool wantTrue, uint baseLinear)
                    {
                        if (mask == null || mask.Length == 0)
                            return Array.Empty<LeReachabilityRangeInfo>();

                        var ranges = new List<LeReachabilityRangeInfo>();
                        var inRun = false;
                        var runStart = 0;
                        for (var i = 0; i < mask.Length; i++)
                        {
                            var v = mask[i];
                            if (v == wantTrue)
                            {
                                if (!inRun)
                                {
                                    inRun = true;
                                    runStart = i;
                                }
                            }
                            else
                            {
                                if (inRun)
                                {
                                    inRun = false;
                                    var s = unchecked(baseLinear + (uint)runStart);
                                    var e = unchecked(baseLinear + (uint)i);
                                    if (e > s)
                                        ranges.Add(new LeReachabilityRangeInfo { startLinear = s, endLinear = e });
                                }
                            }
                        }
                        if (inRun)
                        {
                            var s = unchecked(baseLinear + (uint)runStart);
                            var e = unchecked(baseLinear + (uint)mask.Length);
                            if (e > s)
                                ranges.Add(new LeReachabilityRangeInfo { startLinear = s, endLinear = e });
                        }

                        return ranges.OrderBy(r => r.startLinear).ToArray();
                    }

                    var codeRanges = BuildRanges(covered, wantTrue: true, obj.BaseAddress);
                    var dataRanges = BuildRanges(covered, wantTrue: false, obj.BaseAddress);

                    outObjects.Add(new LeReachabilityObjectInfo
                    {
                        index = obj.Index,
                        baseAddress = obj.BaseAddress,
                        virtualSize = obj.VirtualSize,
                        flags = obj.Flags,
                        decodedStartLinear = obj.BaseAddress,
                        decodedEndLinear = execObjDecodedEndLinear.TryGetValue(obj.Index, out var de) ? de : unchecked(obj.BaseAddress + (uint)maxLen),
                        instructionCount = insList.Count,
                        reachableInstructionCount = reachableIns,
                        reachableByteCount = reachableBytes,
                        reachableCodeRanges = codeRanges,
                        dataCandidateRanges = dataRanges,
                    });
                }

                map = new LeReachabilityInfo
                {
                    inputFile = inputFile,
                    entryLinear = entryLinear,
                    objects = outObjects.ToArray(),
                };

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                map = null;
                return false;
            }
        }

        private static void CaptureCfgSnapshot(
            LeAnalysis analysis,
            HashSet<uint> functionStarts,
            HashSet<uint> blockStarts,
            Dictionary<uint, List<uint>> blockPreds)
        {
            if (analysis == null)
                return;
            if (functionStarts == null || functionStarts.Count == 0)
                return;
            if (blockStarts == null || blockStarts.Count == 0)
                return;
            if (blockPreds == null || blockPreds.Count == 0)
                return;

            var sortedFunc = functionStarts.OrderBy(x => x).ToArray();
            var sortedBlocks = blockStarts.OrderBy(x => x).ToArray();

            static uint FindOwnerStart(uint[] sortedStarts, uint addr)
            {
                if (sortedStarts == null || sortedStarts.Length == 0)
                    return 0;
                var idx = Array.BinarySearch(sortedStarts, addr);
                if (idx >= 0)
                    return sortedStarts[idx];
                idx = ~idx - 1;
                if (idx < 0)
                    return 0;
                return sortedStarts[idx];
            }

            static uint FindContainingBlock(uint[] sortedBlockStarts, uint addr)
            {
                if (sortedBlockStarts == null || sortedBlockStarts.Length == 0)
                    return 0;
                var idx = Array.BinarySearch(sortedBlockStarts, addr);
                if (idx >= 0)
                    return sortedBlockStarts[idx];
                idx = ~idx - 1;
                if (idx < 0)
                    return 0;
                return sortedBlockStarts[idx];
            }

            // Ensure function CFG containers exist.
            foreach (var f in sortedFunc)
            {
                if (!analysis.CfgByFunction.ContainsKey(f))
                    analysis.CfgByFunction[f] = new LeFunctionCfg { FunctionStart = f };
            }

            // Seed blocks into their owner function.
            foreach (var b in sortedBlocks)
            {
                var owner = FindOwnerStart(sortedFunc, b);
                if (owner == 0)
                    continue;
                if (!analysis.CfgByFunction.TryGetValue(owner, out var cfg) || cfg == null)
                    continue;
                if (!cfg.Blocks.ContainsKey(b))
                    cfg.Blocks[b] = new LeBasicBlockInfo { Start = b };
            }

            // Convert preds(dst <- srcInsAddr) into block->block edges (best-effort).
            foreach (var kvp in blockPreds)
            {
                var dst = kvp.Key;
                var ownerDst = FindOwnerStart(sortedFunc, dst);
                if (ownerDst == 0)
                    continue;

                foreach (var srcInsAddr in kvp.Value)
                {
                    var srcBlock = FindContainingBlock(sortedBlocks, srcInsAddr);
                    if (srcBlock == 0)
                        continue;
                    var ownerSrc = FindOwnerStart(sortedFunc, srcBlock);
                    if (ownerSrc == 0)
                        continue;

                    // Keep CFG local to a single function for now (per-function export).
                    if (ownerSrc != ownerDst)
                        continue;

                    if (!analysis.CfgByFunction.TryGetValue(ownerSrc, out var cfg) || cfg == null)
                        continue;

                    if (!cfg.Blocks.TryGetValue(srcBlock, out var srcInfo) || srcInfo == null)
                        cfg.Blocks[srcBlock] = srcInfo = new LeBasicBlockInfo { Start = srcBlock };
                    if (!cfg.Blocks.TryGetValue(dst, out var dstInfo) || dstInfo == null)
                        cfg.Blocks[dst] = dstInfo = new LeBasicBlockInfo { Start = dst };

                    if (!srcInfo.Successors.Contains(dst))
                        srcInfo.Successors.Add(dst);
                    if (!dstInfo.Predecessors.Contains(srcBlock))
                        dstInfo.Predecessors.Add(srcBlock);
                }
            }
        }

        private static readonly object _lastAnalysisLock = new object();
        private static LeAnalysis _lastAnalysis;

        public static LeAnalysis GetLastAnalysis()
        {
            lock (_lastAnalysisLock)
                return _lastAnalysis;
        }

        private static void SetLastAnalysis(LeAnalysis analysis)
        {
            lock (_lastAnalysisLock)
                _lastAnalysis = analysis;
        }

        // SharpDisasm's default Instruction.ToString() path uses shared translator state.
        // For parallel insights passes, use a per-thread translator instance.
        private static readonly ThreadLocal<SharpDisasm.Translators.Translator> _tlsIntelTranslator =
            new ThreadLocal<SharpDisasm.Translators.Translator>(() => new SharpDisasm.Translators.IntelTranslator());

        private static string InsText(Instruction ins)
        {
            if (ins == null)
                return string.Empty;

            try
            {
                var tr = _tlsIntelTranslator.Value;
                if (tr != null)
                    return tr.Translate(ins) ?? string.Empty;
            }
            catch
            {
                // Fallback for any unexpected translator failure.
            }

            // Avoid Instruction.ToString() here (not thread-safe under parallel insights).
            return string.Empty;
        }

        private const ushort LE_OBJECT_ENTRY_SIZE = 24;

        private sealed class FunctionSummary
        {
            public uint Start;
            public int InstructionCount;
            public int BlockCount;
            public readonly HashSet<uint> Calls = new HashSet<uint>();
            public readonly HashSet<string> Globals = new HashSet<string>(StringComparer.Ordinal);
            public readonly HashSet<string> Strings = new HashSet<string>(StringComparer.Ordinal);

            public string ToComment()
            {
                var calls = Calls.Count > 0 ? string.Join(", ", Calls.OrderBy(x => x).Take(12).Select(x => $"func_{x:X8}")) : "(none)";
                var globs = Globals.Count > 0 ? string.Join(", ", Globals.OrderBy(x => x).Take(12)) : "(none)";
                var strs = Strings.Count > 0 ? string.Join(", ", Strings.OrderBy(x => x).Take(12)) : "(none)";
                return $"; SUMMARY: ins={InstructionCount} blocks={BlockCount} calls={calls} globals={globs} strings={strs}";
            }
        }

        private static readonly Regex EbpDispRegex = new Regex(
            "\\[(?<reg>ebp)\\s*(?<sign>[\\+\\-])\\s*(?<hex>0x[0-9A-Fa-f]+)\\]",
            RegexOptions.Compiled);
        private static readonly Regex MovRegRegRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<src>e[a-z]{2})$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MovRegFromArgRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*\[arg_(?<arg>[0-9]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MovRegFromEbpDispRegex = new Regex(
            @"^mov\s+(?<dst>e[a-z]{2}),\s*\[ebp\s*\+\s*(?<hex>0x[0-9A-Fa-f]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex LeaRegFromArgRegex = new Regex(
            @"^lea\s+(?<dst>e[a-z]{2}),\s*\[arg_(?<arg>[0-9]+)\]$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex WritesRegRegex = new Regex(
            @"^(?<mn>mov|lea|add|sub|xor|and|or|imul|shl|shr|sar|rol|ror|inc|dec|pop|xchg)\s+(?<dst>e[a-z]{2})\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpRegex = new Regex(
            @"\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpIndexedRegex = new Regex(
            @"\[(?<base>e[a-z]{2})(?:\+(?<index>e[a-z]{2})\*(?<scale>[0-9]+))?(?:(?<sign>[\+\-])0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex MemOpWithSizeRegex = new Regex(
            @"(?<size>byte|word|dword)\s+\[(?<base>e[a-z]{2})(?:\+0x(?<disp>[0-9A-Fa-f]+))?\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovDxImm16Regex = new Regex(
            @"^mov\s+dx,\s*(?<imm>0x[0-9A-Fa-f]+)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovEdxImmRegex = new Regex(
            @"^mov\s+edx,\s*(?<imm>0x[0-9A-Fa-f]+)$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex OutDxAlRegex = new Regex(
            @"^out\s+dx,\s*al$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex OutDxAxRegex = new Regex(
            @"^out\s+dx,\s*ax$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex InAlDxRegex = new Regex(
            @"^in\s+al,\s*dx$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static void SplitInstructionAndComments(string insText, out string instruction, out List<string> comments)
        {
            instruction = insText ?? string.Empty;
            comments = new List<string>();
            if (string.IsNullOrEmpty(insText))
                return;

            var parts = insText.Split(new[] { " ; " }, StringSplitOptions.None);
            if (parts.Length <= 1)
                return;

            instruction = parts[0];
            comments = parts.Skip(1).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToList();
        }

        private static IEnumerable<string> WrapText(string text, int maxWidth)
        {
            if (string.IsNullOrEmpty(text))
                yield break;

            if (maxWidth <= 8)
            {
                yield return text;
                yield break;
            }

            var t = text.Trim();
            while (t.Length > maxWidth)
            {
                var breakAt = t.LastIndexOf(' ', maxWidth);
                if (breakAt <= 0)
                    breakAt = maxWidth;

                var line = t[..breakAt].TrimEnd();
                if (!string.IsNullOrEmpty(line))
                    yield return line;

                t = t[breakAt..].TrimStart();
            }

            if (t.Length > 0)
                yield return t;
        }

        private static void AppendWrappedDisasmLine(StringBuilder sb, string prefix, string insText, int commentColumn, int maxWidth, int minGapAfterInstruction = 14)
        {
            if (sb == null)
                return;

            SplitInstructionAndComments(insText, out var instruction, out var comments);
            var baseLine = (prefix ?? string.Empty) + (instruction ?? string.Empty);
            if (comments == null || comments.Count == 0)
            {
                sb.AppendLine(baseLine);
                return;
            }

            var startCol = Math.Max(0, commentColumn);
            if (!string.IsNullOrEmpty(baseLine) && baseLine.Length >= startCol)
                startCol = baseLine.Length + Math.Max(1, minGapAfterInstruction);

            var commentIndent = new string(' ', startCol);
            var first = true;

            foreach (var c in comments)
            {
                foreach (var wrapped in WrapText(c, Math.Max(16, maxWidth - (startCol + 2))))
                {
                    if (first)
                    {
                        var line = baseLine;
                        if (line.Length < startCol)
                            line += new string(' ', startCol - line.Length);
                        else if (!string.IsNullOrEmpty(line))
                            line += new string(' ', Math.Max(1, minGapAfterInstruction));
                        line += $"; {wrapped}";
                        sb.AppendLine(line);
                        first = false;
                    }
                    else
                    {
                        sb.AppendLine($"{commentIndent}; {wrapped}");
                    }
                }
            }
        }

        private sealed class FieldAccessStats
        {
            public int ReadCount;
            public int WriteCount;
            public string Size = string.Empty;
            public int PointerUseCount;
            public readonly Dictionary<int, int> IndexScaleCounts = new Dictionary<int, int>();
            public readonly Dictionary<uint, int> ArrayBoundCounts = new Dictionary<uint, int>();
        }

        private static void RecordFieldIndexScale(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            int scale)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias) || scale <= 0)
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.IndexScaleCounts.TryGetValue(scale, out var c);
            st.IndexScaleCounts[scale] = c + 1;
        }

        private static int? GetMostCommonIndexScale(FieldAccessStats st)
        {
            if (st == null || st.IndexScaleCounts == null || st.IndexScaleCounts.Count == 0)
                return null;

            // Require at least 2 hits to avoid noisy one-offs.
            var best = st.IndexScaleCounts.OrderByDescending(k => k.Value).ThenBy(k => k.Key).FirstOrDefault();
            return best.Value >= 2 ? best.Key : null;
        }

        private static uint? GetMostCommonArrayBound(FieldAccessStats st)
        {
            if (st == null || st.ArrayBoundCounts == null || st.ArrayBoundCounts.Count == 0)
                return null;

            var best = st.ArrayBoundCounts.OrderByDescending(k => k.Value).ThenBy(k => k.Key).FirstOrDefault();
            if (best.Value >= 2)
                return best.Key;

            // If we only ever saw one bound value for this field, a single hit can still be useful.
            // (Keeps things conservative: avoids emitting when multiple different bounds were observed.)
            return st.ArrayBoundCounts.Count == 1 && best.Value >= 1 ? best.Key : null;
        }

        private static void RecordFieldArrayBound(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            uint bound)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias))
                return;
            if (bound == 0 || bound > 0x100000)
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();
            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.ArrayBoundCounts.TryGetValue(bound, out var c);
            st.ArrayBoundCounts[bound] = c + 1;
        }

        private static string FormatFieldExtraHints(FieldAccessStats st)
        {
            if (st == null)
                return string.Empty;

            var hints = new List<string>();

            var ptr = st.PointerUseCount > 0 && (string.IsNullOrEmpty(st.Size) || string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase));
            if (ptr)
                hints.Add("ptr");

            var scale = GetMostCommonIndexScale(st);
            if (scale.HasValue)
                hints.Add($"arr*{scale.Value}");

            var bound = GetMostCommonArrayBound(st);
            if (bound.HasValue)
                hints.Add($"n~0x{bound.Value:X}");

            return hints.Count == 0 ? string.Empty : " " + string.Join(" ", hints);
        }

        private static string BitWidthToMemSize(int bits)
        {
            return bits switch
            {
                8 => "byte",
                16 => "word",
                32 => "dword",
                _ => string.Empty
            };
        }

        private static string InferMemOperandSize(string insText, string memOperandText)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(memOperandText))
                return string.Empty;

            // Prefer explicit size tokens close to the memory operand.
            var m = Regex.Match(insText, $@"\b(?<sz>byte|word|dword)\s*{Regex.Escape(memOperandText)}\b", RegexOptions.IgnoreCase);
            if (m.Success)
                return m.Groups["sz"].Value.ToLowerInvariant();

            // Best-effort: infer from register operand width for common ops.
            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = sp > 0 ? t.Substring(0, sp).ToLowerInvariant() : t.ToLowerInvariant();

            // movzx/movsx source width should be explicit; don't guess.
            if (mnemonic == "movzx" || mnemonic == "movsx")
                return string.Empty;

            var ops = sp > 0 ? t.Substring(sp + 1) : string.Empty;
            var parts = ops.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            if (parts.Count < 2)
                return string.Empty;

            var op0 = parts[0];
            var memIsDest = op0.Contains(memOperandText, StringComparison.OrdinalIgnoreCase);
            var other = memIsDest ? parts[1] : parts[0];
            var bits = GetRegBitWidth(other);
            return bits.HasValue ? BitWidthToMemSize(bits.Value) : string.Empty;
        }

        private static bool TryParseEbpArgIndex(string hex, out int argIndex)
        {
            argIndex = -1;
            if (!TryParseHexUInt(hex, out var offU))
                return false;

            var off = (int)offU;
            if (off < 8)
                return false;
            if ((off - 8) % 4 != 0)
                return false;
            argIndex = (off - 8) / 4;
            return argIndex >= 0;
        }

        private static void UpdatePointerAliases(string insText, Dictionary<string, string> aliases, Dictionary<uint, string> ptrSymbols = null)
        {
            if (aliases == null || string.IsNullOrEmpty(insText))
                return;

            // Normalize spacing a bit for regexes.
            var t = insText.Trim();

            // Propagate pointer aliases: mov dst, src
            var mrr = MovRegRegRegex.Match(t);
            if (mrr.Success)
            {
                var dst = mrr.Groups["dst"].Value.ToLowerInvariant();
                var src = mrr.Groups["src"].Value.ToLowerInvariant();
                if (aliases.TryGetValue(src, out var a))
                    aliases[dst] = a;
                else
                    aliases.Remove(dst);
                return;
            }

            // mov dst, [arg_N]
            var mfa = MovRegFromArgRegex.Match(t);
            if (mfa.Success)
            {
                var dst = mfa.Groups["dst"].Value.ToLowerInvariant();
                var arg = mfa.Groups["arg"].Value;
                aliases[dst] = $"arg{arg}";
                return;
            }

            // lea dst, [arg_N]
            var lfa = LeaRegFromArgRegex.Match(t);
            if (lfa.Success)
            {
                var dst = lfa.Groups["dst"].Value.ToLowerInvariant();
                var arg = lfa.Groups["arg"].Value;
                aliases[dst] = $"arg{arg}";
                return;
            }

            // mov dst, [ebp+0xNN] (before stack rewrite) => argK if it matches a typical arg slot
            var mebp = MovRegFromEbpDispRegex.Match(t);
            if (mebp.Success)
            {
                var dst = mebp.Groups["dst"].Value.ToLowerInvariant();
                var hex = mebp.Groups["hex"].Value;
                if (TryParseEbpArgIndex(hex, out var argIndex))
                {
                    aliases[dst] = $"arg{argIndex}";
                    return;
                }
            }

            // mov dst, [abs] => if abs is an inferred pointer global, treat dst as that pointer base
            if (ptrSymbols != null && ptrSymbols.Count > 0)
            {
                if (TryParseMovRegFromAbs(t, out var dstReg, out var abs) && ptrSymbols.TryGetValue(abs, out var ptrName))
                {
                    aliases[dstReg] = ptrName;
                    return;
                }
            }

            // If instruction writes to a register in some other way, drop its alias to avoid staleness.
            var wr = WritesRegRegex.Match(t);
            if (wr.Success)
            {
                var dst = wr.Groups["dst"].Value.ToLowerInvariant();
                if (dst != "ecx")
                    aliases.Remove(dst);
            }
        }

        private static void RecordFieldAccess(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp,
            int readInc,
            int writeInc,
            string size)
        {
            if (statsByBase == null || string.IsNullOrEmpty(baseAlias))
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            if (!string.IsNullOrEmpty(size) && string.IsNullOrEmpty(st.Size))
                st.Size = size;
            else if (!string.IsNullOrEmpty(size) && !string.IsNullOrEmpty(st.Size) && !string.Equals(st.Size, size, StringComparison.OrdinalIgnoreCase))
                st.Size = string.Empty;

            if (readInc > 0)
                st.ReadCount += readInc;
            if (writeInc > 0)
                st.WriteCount += writeInc;
        }

        private static void RecordFieldPointerUse(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            string baseAlias,
            uint disp)
        {
            if (statsByBase == null || string.IsNullOrWhiteSpace(baseAlias))
                return;

            if (!statsByBase.TryGetValue(baseAlias, out var byDisp))
                statsByBase[baseAlias] = byDisp = new Dictionary<uint, FieldAccessStats>();

            if (!byDisp.TryGetValue(disp, out var st))
                byDisp[disp] = st = new FieldAccessStats();

            st.PointerUseCount++;
        }

        private static void GetMemAccessRW(string insText, string memOperandText, out int reads, out int writes)
        {
            reads = 0;
            writes = 0;

            if (string.IsNullOrEmpty(insText) || string.IsNullOrEmpty(memOperandText))
                return;

            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = sp > 0 ? t.Substring(0, sp).ToLowerInvariant() : t.ToLowerInvariant();

            // Split operands roughly (best-effort).
            var ops = sp > 0 ? t.Substring(sp + 1) : string.Empty;
            var parts = ops.Split(',').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            var op0 = parts.Count > 0 ? parts[0] : string.Empty;

            var memIsDest = !string.IsNullOrEmpty(op0) && op0.Contains(memOperandText, StringComparison.OrdinalIgnoreCase);

            // Treat various instruction families.
            if (mnemonic == "mov")
            {
                if (memIsDest)
                    writes = 1;
                else
                    reads = 1;
                return;
            }

            switch (mnemonic)
            {
                // Read-modify-write when memory is destination.
                case "add":
                case "sub":
                case "and":
                case "or":
                case "xor":
                case "adc":
                case "sbb":
                case "imul":
                case "shl":
                case "shr":
                case "sar":
                case "rol":
                case "ror":
                case "inc":
                case "dec":
                case "xchg":
                    if (memIsDest)
                    {
                        reads = 1;
                        writes = 1;
                    }
                    else
                    {
                        reads = 1;
                    }
                    return;

                case "cmp":
                case "test":
                    reads = 1;
                    return;

                default:
                    reads = 1;
                    return;
            }
        }

        private static void CollectFieldAccessesForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive,
            out Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase,
            Dictionary<uint, string> ptrSymbols = null)
        {
            statsByBase = new Dictionary<string, Dictionary<uint, FieldAccessStats>>(StringComparer.Ordinal);
            if (instructions == null || startIdx < 0 || endIdxExclusive > instructions.Count || startIdx >= endIdxExclusive)
                return;

            // Track pointer-ish aliases: ecx is likely this.
            var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ecx"] = "this"
            };

            var regFromField = new Dictionary<string, (string baseAlias, uint disp)>(StringComparer.OrdinalIgnoreCase);

            static uint? FindNearbyCmpImmBoundForIndex(List<Instruction> insList, int idx, int start, int end, string indexReg)
            {
                if (insList == null || string.IsNullOrWhiteSpace(indexReg))
                    return null;
                static string CanonReg(string r)
                {
                    if (string.IsNullOrWhiteSpace(r))
                        return string.Empty;
                    r = r.Trim().ToLowerInvariant();
                    return r switch
                    {
                        "al" or "ah" or "ax" or "eax" => "eax",
                        "bl" or "bh" or "bx" or "ebx" => "ebx",
                        "cl" or "ch" or "cx" or "ecx" => "ecx",
                        "dl" or "dh" or "dx" or "edx" => "edx",
                        "si" or "esi" => "esi",
                        "di" or "edi" => "edi",
                        _ => r,
                    };
                }

                indexReg = CanonReg(indexReg);
                if (indexReg == "esp" || indexReg == "ebp")
                    return null;

                // Most bounds checks happen before the indexed access; scan backward a bit.
                var lo = Math.Max(start, idx - 96);
                var candidateRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { indexReg };
                var candidateStackSyms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Track (best-effort) constants loaded into registers within the scan window so we can
                // treat `cmp idx, regConst` as a bounds check.
                var regConst = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
                var regClobbered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Track constants stored into stack locals/args so we can match `cmp idx, [local]`.
                var stackConst = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
                var stackClobbered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Prefer cmp-based bounds (direct checks) over mask-based bounds.
                (uint bound, int distance)? bestCmp = null;
                (uint bound, int distance)? bestMask = null;

                static bool TryMaskToBound(uint mask, out uint bound)
                {
                    bound = 0;
                    if (mask == 0)
                        return false;
                    // mask is (2^k - 1) iff mask & (mask+1) == 0
                    var plus = mask + 1;
                    if ((mask & plus) != 0)
                        return false;
                    bound = plus;
                    return true;
                }

                static void RecordBest(ref (uint bound, int distance)? best, uint bound, int distance)
                {
                    if (bound == 0)
                        return;
                    if (best == null || distance < best.Value.distance)
                        best = (bound, distance);
                }
                for (var j = idx - 1; j >= lo; j--)
                {
                    var t = InsText(insList[j]).Trim();
                    if (t.Length == 0)
                        continue;

                    var dist = idx - j;

                    // Don't scan across clear control-flow boundaries.
                    if (t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp ", StringComparison.OrdinalIgnoreCase))
                        break;

                    // Bounds by bitmask: `and idx, (2^k-1)` implies idx in [0..(2^k-1)], so n = 2^k.
                    // This is common when indexing fixed-size tables.
                    var andRegImm = Regex.Match(
                        t,
                        @"^and\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (andRegImm.Success)
                    {
                        var rr = CanonReg(andRegImm.Groups["reg"].Value);
                        if (candidateRegs.Contains(rr) && TryParseHexOrDecUInt32(andRegImm.Groups["imm"].Value, out var mask) && TryMaskToBound(mask, out var b) && b > 0)
                            RecordBest(ref bestMask, b, dist);
                    }

                    var andStackImm = Regex.Match(
                        t,
                        @"^and\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (andStackImm.Success)
                    {
                        var sym = andStackImm.Groups["sym"].Value;
                        if (candidateStackSyms.Contains(sym) && TryParseHexOrDecUInt32(andStackImm.Groups["imm"].Value, out var mask) && TryMaskToBound(mask, out var b) && b > 0)
                            RecordBest(ref bestMask, b, dist);
                    }

                    // Stack slot constants.
                    var movStackImm = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackImm.Success)
                    {
                        var sym = movStackImm.Groups["sym"].Value;
                        if (!stackConst.ContainsKey(sym) && !stackClobbered.Contains(sym))
                        {
                            if (TryParseHexOrDecUInt32(movStackImm.Groups["imm"].Value, out var su) && su > 0)
                                stackConst[sym] = su;
                            else
                                stackClobbered.Add(sym);
                        }
                    }

                    var movStackReg = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackReg.Success)
                    {
                        var sym = movStackReg.Groups["sym"].Value;
                        if (!stackConst.ContainsKey(sym) && !stackClobbered.Contains(sym))
                        {
                            var src = CanonReg(movStackReg.Groups["src"].Value);
                            if (regConst.TryGetValue(src, out var ru) && ru > 0)
                                stackConst[sym] = ru;
                            else
                                stackClobbered.Add(sym);
                        }
                    }

                    // Record immediate constants assigned to registers.
                    // Because we're scanning backward, only accept the *first* assignment we see for a reg
                    // (i.e., closest to the use), and ignore if we've seen other writes to that reg.
                    var movImm = Regex.Match(
                        t,
                        @"^mov\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movImm.Success)
                    {
                        var dst = CanonReg(movImm.Groups["dst"].Value);
                        if (!regConst.ContainsKey(dst) && !regClobbered.Contains(dst))
                        {
                            if (TryParseHexOrDecUInt32(movImm.Groups["imm"].Value, out var u) && u > 0)
                                regConst[dst] = u;
                            else
                                regClobbered.Add(dst);
                        }
                    }

                    // Track other simple writes that should invalidate constant provenance.
                    var writesReg = Regex.Match(
                        t,
                        @"^(?:add|sub|imul|idiv|div|and|or|xor|shl|shr|sar|rol|ror|inc|dec|lea|pop)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\b",
                        RegexOptions.IgnoreCase);
                    if (writesReg.Success)
                    {
                        var dst = CanonReg(writesReg.Groups["dst"].Value);
                        if (!regConst.ContainsKey(dst))
                            regClobbered.Add(dst);
                    }

                    // Track reg <-> [local_X]/[arg_Y] so we can match cmp [local_X], imm style bounds checks.
                    // Keep this conservative: only stack symbols (locals/args), not arbitrary memory.
                    var movRegFromStack = Regex.Match(
                        t,
                        @"^(?:mov|movsx|movzx)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*$",
                        RegexOptions.IgnoreCase);
                    if (movRegFromStack.Success)
                    {
                        var dst = CanonReg(movRegFromStack.Groups["dst"].Value);
                        var sym = movRegFromStack.Groups["sym"].Value;
                        if (candidateRegs.Contains(dst))
                            candidateStackSyms.Add(sym);
                    }

                    var movStackFromReg = Regex.Match(
                        t,
                        @"^mov\s+\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (movStackFromReg.Success)
                    {
                        var src = CanonReg(movStackFromReg.Groups["src"].Value);
                        var sym = movStackFromReg.Groups["sym"].Value;
                        if (candidateRegs.Contains(src))
                            candidateStackSyms.Add(sym);
                    }

                    // Track simple register-to-register moves so we can match a cmp against a source reg.
                    var mv = Regex.Match(
                        t,
                        @"^(?:mov|movsx|movzx)\s+(?<dst>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<src>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (mv.Success)
                    {
                        var dst = CanonReg(mv.Groups["dst"].Value);
                        var src = CanonReg(mv.Groups["src"].Value);
                        if (candidateRegs.Contains(dst))
                            candidateRegs.Add(src);
                    }

                    var m = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);

                    if (m.Success)
                    {
                        var reg = CanonReg(m.Groups["reg"].Value);
                        if (candidateRegs.Contains(reg) && TryParseHexOrDecUInt32(m.Groups["imm"].Value, out var u) && u > 0)
                            RecordBest(ref bestCmp, u, dist);
                        continue;
                    }

                    // cmp <reg>, <regConst>
                    var mrr = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<r1>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?(?<r2>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (mrr.Success)
                    {
                        var r1 = CanonReg(mrr.Groups["r1"].Value);
                        var r2 = CanonReg(mrr.Groups["r2"].Value);
                        if (candidateRegs.Contains(r1) && regConst.TryGetValue(r2, out var b) && b > 0)
                            RecordBest(ref bestCmp, b, dist);
                        if (candidateRegs.Contains(r2) && regConst.TryGetValue(r1, out var b2) && b2 > 0)
                            RecordBest(ref bestCmp, b2, dist);
                        continue;
                    }

                    // cmp <candidateReg>, [stackSymConst]
                    var mrs = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*,\s*(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*$",
                        RegexOptions.IgnoreCase);
                    if (mrs.Success)
                    {
                        var rr = CanonReg(mrs.Groups["reg"].Value);
                        var sym = mrs.Groups["sym"].Value;
                        if (candidateRegs.Contains(rr) && candidateStackSyms.Contains(sym) && stackConst.TryGetValue(sym, out var b4) && b4 > 0)
                            RecordBest(ref bestCmp, b4, dist);
                        continue;
                    }

                    // cmp [stackSymConst], <candidateReg>
                    var msr2 = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                        RegexOptions.IgnoreCase);
                    if (msr2.Success)
                    {
                        var sym = msr2.Groups["sym"].Value;
                        var rr = CanonReg(msr2.Groups["reg"].Value);
                        if (candidateRegs.Contains(rr) && candidateStackSyms.Contains(sym) && stackConst.TryGetValue(sym, out var b5) && b5 > 0)
                            RecordBest(ref bestCmp, b5, dist);
                        continue;
                    }

                    var m2 = Regex.Match(
                        t,
                        @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$",
                        RegexOptions.IgnoreCase);
                    if (!m2.Success)
                    {
                        // cmp [stackSym], regConst
                        var msr = Regex.Match(
                            t,
                            @"^cmp\s+(?:(?:byte|word|dword)\s+)?\[(?<sym>local_[0-9A-Fa-f]+|arg_[0-9A-Fa-f]+)\]\s*,\s*(?:(?:byte|word|dword)\s+)?(?<reg>e?[abcd]x|[abcd][hl]|[abcd]x|e?[sd]i|[sd]i)\s*$",
                            RegexOptions.IgnoreCase);
                        if (msr.Success)
                        {
                            var sym = msr.Groups["sym"].Value;
                            var rr = CanonReg(msr.Groups["reg"].Value);
                            if (candidateStackSyms.Contains(sym) && regConst.TryGetValue(rr, out var b3) && b3 > 0)
                                RecordBest(ref bestCmp, b3, dist);
                        }
                        continue;
                    }

                    var sym2 = m2.Groups["sym"].Value;
                    if (!candidateStackSyms.Contains(sym2))
                        continue;

                    if (TryParseHexOrDecUInt32(m2.Groups["imm"].Value, out var u2) && u2 > 0)
                        RecordBest(ref bestCmp, u2, dist);
                }

                if (bestCmp.HasValue)
                    return bestCmp.Value.bound;

                // Mask-derived bounds are weaker; require they be reasonably close to the access.
                if (bestMask.HasValue && bestMask.Value.distance <= 16)
                    return bestMask.Value.bound;

                return null;
            }

            for (var i = startIdx; i < endIdxExclusive; i++)
            {
                var insText = InsText(instructions[i]).Trim();

                // Update aliases first so we model dataflow forward.
                UpdatePointerAliases(insText, aliases, ptrSymbols);

                // If instruction writes to a register in some other way, drop reg->field provenance.
                var wr = WritesRegRegex.Match(insText);
                if (wr.Success)
                {
                    var dst = wr.Groups["dst"].Value.ToLowerInvariant();
                    regFromField.Remove(dst);
                }

                // Seed provenance on simple loads: mov reg32, [base+disp]
                var mLoad = Regex.Match(insText, @"^mov\s+(?<dst>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<mem>\[[^\]]+\])\s*$", RegexOptions.IgnoreCase);
                if (mLoad.Success)
                {
                    var dst = mLoad.Groups["dst"].Value.ToLowerInvariant();
                    if (GetRegBitWidth(dst).GetValueOrDefault() == 32)
                    {
                        var mem = mLoad.Groups["mem"].Value;
                        var mm = MemOpRegex.Match(mem);
                        if (mm.Success)
                        {
                            var baseReg = mm.Groups["base"].Value.ToLowerInvariant();
                            if (baseReg != "esp" && baseReg != "ebp")
                            {
                                if (!aliases.TryGetValue(baseReg, out var baseAlias))
                                    baseAlias = baseReg == "ecx" ? "this" : null;

                                if (!string.IsNullOrEmpty(baseAlias))
                                {
                                    var disp = 0u;
                                    if (mm.Groups["disp"].Success)
                                        disp = Convert.ToUInt32(mm.Groups["disp"].Value, 16);
                                    if (disp <= 0x4000)
                                        regFromField[dst] = (baseAlias, disp);
                                }
                            }
                        }
                    }
                }

                foreach (Match m in MemOpIndexedRegex.Matches(insText))
                {
                    var baseReg = m.Groups["base"].Value.ToLowerInvariant();
                    if (baseReg == "esp" || baseReg == "ebp")
                        continue;

                    if (regFromField.TryGetValue(baseReg, out var srcField))
                        RecordFieldPointerUse(statsByBase, srcField.baseAlias, srcField.disp);

                    if (!aliases.TryGetValue(baseReg, out var baseAlias))
                    {
                        if (baseReg == "ecx")
                            baseAlias = "this";
                        else
                            continue;
                    }

                    var disp = 0u;
                    if (m.Groups["disp"].Success)
                    {
                        disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);
                        if (m.Groups["sign"].Success && m.Groups["sign"].Value == "-")
                        {
                            // Negative displacements aren't meaningful as struct fields.
                            continue;
                        }
                    }

                    // Avoid treating huge displacements as struct fields; these are often absolute tables
                    // or misclassified addressing modes.
                    if (disp > 0x4000)
                        continue;

                    // Best-effort per-operand read/write classification.
                    var memText = m.Value; // e.g. [ecx+0x10]
                    GetMemAccessRW(insText, memText, out var r, out var w);
                    var size = InferMemOperandSize(insText, memText);
                    RecordFieldAccess(statsByBase, baseAlias, disp, r, w, size);

                    if (m.Groups["index"].Success && m.Groups["scale"].Success && int.TryParse(m.Groups["scale"].Value, out var scale) && (scale == 2 || scale == 4 || scale == 8))
                    {
                        RecordFieldIndexScale(statsByBase, baseAlias, disp, scale);

                        // If we can see a repeated compare against a constant on the index, treat it as an array bound candidate.
                        var idxReg = m.Groups["index"].Value.ToLowerInvariant();
                        var bound = FindNearbyCmpImmBoundForIndex(instructions, i, startIdx, endIdxExclusive, idxReg);
                        if (bound.HasValue)
                            RecordFieldArrayBound(statsByBase, baseAlias, disp, bound.Value);
                    }
                }
            }
        }

        private static string FormatFieldSummary(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            // Keep it compact: show up to 2 bases, 6 fields each.
            var parts = new List<string>();
            foreach (var baseKvp in statsByBase.OrderByDescending(k => k.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount)).ThenBy(k => k.Key).Take(2))
            {
                var baseAlias = baseKvp.Key;
                var fields = baseKvp.Value
                    // De-noise: drop field_0 unless it looks like a dword vptr/first-field.
                    .Where(k =>
                    {
                        if (k.Key != 0)
                            return true;
                        var st = k.Value;
                        if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                            return true;
                        // If size is unknown, allow only low-frequency field_0.
                        var tot = st.ReadCount + st.WriteCount;
                        return string.IsNullOrEmpty(st.Size) && tot <= 8;
                    })
                    .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                    .ThenBy(k => k.Key)
                    .Take(6)
                    .Select(k =>
                    {
                        var disp = k.Key;
                        var st = k.Value;
                        var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                        var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                        var extra = FormatFieldExtraHints(st);
                        return $"+0x{disp:X}({rw}{sz}{extra})";
                    });
                parts.Add($"{baseAlias}: {string.Join(", ", fields)}");
            }

            if (parts.Count == 0)
                return string.Empty;
            return $"FIELDS: {string.Join(" | ", parts)}";
        }

        private static void MergeFieldStats(
            Dictionary<string, Dictionary<uint, FieldAccessStats>> dst,
            Dictionary<string, Dictionary<uint, FieldAccessStats>> src,
            Func<string, bool> baseFilter = null)
        {
            if (dst == null || src == null)
                return;

            foreach (var baseKvp in src)
            {
                if (string.IsNullOrWhiteSpace(baseKvp.Key))
                    continue;
                if (baseFilter != null && !baseFilter(baseKvp.Key))
                    continue;

                if (!dst.TryGetValue(baseKvp.Key, out var byDispDst))
                    dst[baseKvp.Key] = byDispDst = new Dictionary<uint, FieldAccessStats>();

                foreach (var dispKvp in baseKvp.Value)
                {
                    if (!byDispDst.TryGetValue(dispKvp.Key, out var stDst))
                        byDispDst[dispKvp.Key] = stDst = new FieldAccessStats();

                    var stSrc = dispKvp.Value;
                    stDst.ReadCount += stSrc.ReadCount;
                    stDst.WriteCount += stSrc.WriteCount;
                    stDst.PointerUseCount += stSrc.PointerUseCount;

                    if (stSrc.IndexScaleCounts != null && stSrc.IndexScaleCounts.Count > 0)
                    {
                        foreach (var sc in stSrc.IndexScaleCounts)
                        {
                            stDst.IndexScaleCounts.TryGetValue(sc.Key, out var c);
                            stDst.IndexScaleCounts[sc.Key] = c + sc.Value;
                        }
                    }

                    if (stSrc.ArrayBoundCounts != null && stSrc.ArrayBoundCounts.Count > 0)
                    {
                        foreach (var bc in stSrc.ArrayBoundCounts)
                        {
                            stDst.ArrayBoundCounts.TryGetValue(bc.Key, out var c);
                            stDst.ArrayBoundCounts[bc.Key] = c + bc.Value;
                        }
                    }

                    if (string.IsNullOrEmpty(stDst.Size))
                    {
                        stDst.Size = stSrc.Size;
                    }
                    else if (!string.IsNullOrEmpty(stSrc.Size) && !string.Equals(stDst.Size, stSrc.Size, StringComparison.OrdinalIgnoreCase))
                    {
                        // Conflicting sizes across uses; leave blank to avoid misleading.
                        stDst.Size = string.Empty;
                    }
                }
            }
        }

        private static string FormatPointerStructTable(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            var ptrBases = statsByBase
                .Where(k => k.Key != null && k.Key.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                .Select(k => new
                {
                    Base = k.Key,
                    Total = k.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount),
                    Fields = k.Value
                })
                .Where(x => x.Total > 0)
                .OrderByDescending(x => x.Total)
                .ThenBy(x => x.Base)
                .Take(10)
                .ToList();

            if (ptrBases.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine(";");
            sb.AppendLine("; Inferred Pointer Struct Tables (best-effort, aggregated field access stats)");
            foreach (var b in ptrBases)
            {
                // Keep each struct compact: up to 10 fields, dropping +0 unless it looks important.
                var fields = b.Fields
                    .Where(k =>
                    {
                        if (k.Key != 0)
                            return true;
                        var st = k.Value;
                        if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                            return true;
                        var tot = st.ReadCount + st.WriteCount;
                        return string.IsNullOrEmpty(st.Size) && tot <= 8;
                    })
                    .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                    .ThenBy(k => k.Key)
                    .Take(10)
                    .Select(k =>
                    {
                        var disp = k.Key;
                        var st = k.Value;
                        var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                        var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                        var extra = FormatFieldExtraHints(st);
                        return $"+0x{disp:X}({rw}{sz}{extra})";
                    })
                    .ToList();

                if (fields.Count == 0)
                    continue;

                sb.AppendLine($"; STRUCT {b.Base}: {string.Join(", ", fields)}");
            }
            sb.AppendLine(";");
            return sb.ToString();
        }

        private static string FormatThisStructTable(Dictionary<string, Dictionary<uint, FieldAccessStats>> statsByBase)
        {
            if (statsByBase == null || statsByBase.Count == 0)
                return string.Empty;

            var thisEntry = statsByBase.FirstOrDefault(k => string.Equals(k.Key, "this", StringComparison.OrdinalIgnoreCase));
            if (string.IsNullOrWhiteSpace(thisEntry.Key) || thisEntry.Value == null || thisEntry.Value.Count == 0)
                return string.Empty;

            var total = thisEntry.Value.Sum(x => x.Value.ReadCount + x.Value.WriteCount);
            if (total <= 0)
                return string.Empty;

            var fields = thisEntry.Value
                .Where(k =>
                {
                    if (k.Key != 0)
                        return true;
                    var st = k.Value;
                    if (string.Equals(st.Size, "dword", StringComparison.OrdinalIgnoreCase))
                        return true;
                    var tot = st.ReadCount + st.WriteCount;
                    return string.IsNullOrEmpty(st.Size) && tot <= 8;
                })
                .OrderByDescending(k => k.Value.ReadCount + k.Value.WriteCount)
                .ThenBy(k => k.Key)
                .Take(12)
                .Select(k =>
                {
                    var disp = k.Key;
                    var st = k.Value;
                    var rw = $"r{st.ReadCount}/w{st.WriteCount}";
                    var sz = string.IsNullOrEmpty(st.Size) ? "" : $" {st.Size}";
                    var extra = FormatFieldExtraHints(st);
                    return $"+0x{disp:X}({rw}{sz}{extra})";
                })
                .ToList();

            if (fields.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine(";");
            sb.AppendLine("; Inferred 'this' Struct Table (best-effort, aggregated field access stats)");
            sb.AppendLine($"; STRUCT this: {string.Join(", ", fields)}");
            sb.AppendLine(";");
            return sb.ToString();
        }

        private static string RewriteFieldOperands(string insText, Dictionary<string, string> aliases)
        {
            if (string.IsNullOrEmpty(insText) || aliases == null || aliases.Count == 0)
                return insText;

            // Rewrite [reg+0xNN] -> [alias+field_NN] for aliases like this/arg0.
            return MemOpRegex.Replace(insText, m =>
            {
                var baseReg = m.Groups["base"].Value.ToLowerInvariant();
                if (baseReg == "esp" || baseReg == "ebp")
                    return m.Value;

                if (!aliases.TryGetValue(baseReg, out var a))
                {
                    if (baseReg == "ecx")
                        a = "this";
                    else
                        return m.Value;
                }

                var disp = 0u;
                if (m.Groups["disp"].Success)
                    disp = Convert.ToUInt32(m.Groups["disp"].Value, 16);

                // Avoid rewriting huge displacements (often absolute addresses or jump tables already handled elsewhere).
                if (disp > 0x4000)
                    return m.Value;

                // Use field_0 for vptr-like deref.
                // For inferred pointer globals (ptr_XXXXXXXX), prefer addition form: [ptr_XXXXXXXX+field_0030]
                if (a.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                {
                    return disp == 0
                        ? $"[{a}+field_0000]"
                        : $"[{a}+field_{disp:X4}]";
                }

                return disp == 0
                    ? $"[{a}+field_0]"
                    : $"[{a}+field_{disp:X}]";
            });
        }

        private sealed class FpuStats
        {
            public int Total;
            public Dictionary<string, int> MnemonicCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public bool HasConvert;
            public bool HasCompare;
            public bool HasFld1;
            public bool HasFldz;
        }

        private static void CollectFpuOpsForFunction(List<Instruction> instructions, int startIdx, int endIdx, out FpuStats stats)
        {
            stats = new FpuStats();
            if (instructions == null || startIdx < 0 || endIdx > instructions.Count || startIdx >= endIdx)
                return;

            for (var i = startIdx; i < endIdx; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                var sp = t.IndexOf(' ');
                var mnemonic = (sp > 0 ? t.Substring(0, sp) : t).Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(mnemonic))
                    continue;

                // Best-effort: x87 mnemonics are typically 'f*' (fld/fstp/fmul/...)
                if (!mnemonic.StartsWith('f'))
                    continue;

                stats.Total++;
                stats.MnemonicCounts.TryGetValue(mnemonic, out var c);
                stats.MnemonicCounts[mnemonic] = c + 1;

                if (mnemonic.StartsWith("fild", StringComparison.OrdinalIgnoreCase) || mnemonic.StartsWith("fist", StringComparison.OrdinalIgnoreCase))
                    stats.HasConvert = true;
                if (mnemonic.StartsWith("fcom", StringComparison.OrdinalIgnoreCase) || mnemonic.StartsWith("fucom", StringComparison.OrdinalIgnoreCase))
                    stats.HasCompare = true;
                if (mnemonic.Equals("fld1", StringComparison.OrdinalIgnoreCase))
                    stats.HasFld1 = true;
                if (mnemonic.Equals("fldz", StringComparison.OrdinalIgnoreCase))
                    stats.HasFldz = true;
            }
        }

        private static string FormatFpuSummary(FpuStats stats)
        {
            if (stats == null || stats.Total < 4)
                return string.Empty;

            var top = stats.MnemonicCounts
                .OrderByDescending(k => k.Value)
                .ThenBy(k => k.Key)
                .Take(6)
                .Select(k => $"{k.Key}(x{k.Value})")
                .ToList();

            var tags = new List<string>();
            if (stats.HasConvert)
                tags.Add("convert");
            if (stats.HasCompare)
                tags.Add("compare/branch?");
            if (stats.HasFld1 || stats.HasFldz)
                tags.Add("constants");

            var tagText = tags.Count > 0 ? $" ; patterns: {string.Join(", ", tags)}" : string.Empty;
            return $"x87 ops={stats.Total}: {string.Join(", ", top)}{tagText}";
        }

        private static string TryAnnotateCriticalSectionIo(List<Instruction> instructions, int startIdx)
        {
            if (instructions == null || startIdx < 0 || startIdx >= instructions.Count)
                return string.Empty;

            // Critical sections can be fairly long (e.g., VGA register programming).
            // Keep it bounded, but large enough to catch typical cli..sti sequences.
            var cliSearchLimit = Math.Min(instructions.Count, startIdx + 64);
            var cliIdx = -1;
            var stiIdx = -1;

            for (var i = startIdx; i < cliSearchLimit; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.Equals("cli", StringComparison.OrdinalIgnoreCase))
                {
                    cliIdx = i;
                    break;
                }
            }

            if (cliIdx < 0)
                return string.Empty;

            var stiSearchLimit = Math.Min(instructions.Count, cliIdx + 256);
            for (var i = cliIdx + 1; i < stiSearchLimit; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (t.Equals("sti", StringComparison.OrdinalIgnoreCase))
                {
                    stiIdx = i;
                    break;
                }
            }

            if (stiIdx < 0)
                return string.Empty;

            ushort? lastDxImm16 = null;
            var ports = new Dictionary<ushort, IoPortStats>();

            for (var i = cliIdx + 1; i < stiIdx; i++)
            {
                var t = InsText(instructions[i]);
                if (TryParseMovDxImmediate(t, out var dxImm))
                    lastDxImm16 = dxImm;

                if (!TryParseIoAccess(t, lastDxImm16, out var port, out var isWrite, out var _))
                    continue;

                if (!ports.TryGetValue(port, out var st))
                    ports[port] = st = new IoPortStats();
                if (isWrite) st.Writes++; else st.Reads++;
            }

            if (ports.Count == 0)
                return string.Empty;

            var top = ports
                .OrderByDescending(p => p.Value.Reads + p.Value.Writes)
                .ThenBy(p => p.Key)
                .Take(4)
                .Select(p =>
                {
                    KnownIoPorts.TryGetValue(p.Key, out var name);
                    var rw = p.Value.Writes > 0 && p.Value.Reads > 0
                        ? $"r{p.Value.Reads}/w{p.Value.Writes}"
                        : (p.Value.Writes > 0 ? $"w{p.Value.Writes}" : $"r{p.Value.Reads}");
                    return !string.IsNullOrEmpty(name)
                        ? $"{name} (0x{p.Key:X4}) {rw}"
                        : $"0x{p.Key:X4} {rw}";
                })
                .ToList();

            return $"BBHINT: critical section (cli..sti) around I/O: {string.Join(", ", top)}";
        }

        private static bool TryParseCmpReg8Imm8(string insText, out string reg8, out byte imm8)
        {
            reg8 = null;
            imm8 = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples: "cmp al, 0x72" / "cmp al, 72h" / "cmp dl, 0"
            var m = Regex.Match(insText.Trim(), @"^cmp\s+(?<reg>[a-d][lh]|[sd]l|[sb]h)\s*,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg8 = m.Groups["reg"].Value.ToLowerInvariant();
            var tok = m.Groups["imm"].Value.Trim();

            if (!TryParseHexOrDecUInt32(tok, out var u) || u > 0xFF)
                return false;

            imm8 = (byte)u;
            return true;
        }

        private static bool IsEqualityJumpMnemonic(string insText)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var t = insText.Trim();
            var sp = t.IndexOf(' ');
            var mnemonic = (sp > 0 ? t.Substring(0, sp) : t).Trim();

            return mnemonic.Equals("jz", StringComparison.OrdinalIgnoreCase)
                || mnemonic.Equals("je", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatImm8AsChar(byte b)
        {
            if (b >= 0x20 && b <= 0x7E)
            {
                var c = (char)b;
                if (c == '\\' || c == '\'' )
                    return $"'{c}'"; // keep it simple
                return $"'{c}'";
            }
            return string.Empty;
        }

        private static string ShortenInterruptHintForCase(string hint)
        {
            if (string.IsNullOrWhiteSpace(hint))
                return string.Empty;

            var t = hint.Trim();
            if (t.StartsWith("INT21: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT21: ".Length);
            else if (t.StartsWith("INT31: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT31: ".Length);
            else if (t.StartsWith("INT: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("INT: ".Length);

            if (t.StartsWith("DOS API:", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("DOS API:".Length).Trim();

            // Drop extra pointer details.
            var semi = t.IndexOf(';');
            if (semi >= 0)
                t = t.Substring(0, semi).Trim();

            // Keep it compact.
            if (t.Length > 42)
                t = t.Substring(0, 42) + "...";

            return t;
        }

        private static string ShortenIoHintForCase(string hint)
        {
            if (string.IsNullOrWhiteSpace(hint))
                return string.Empty;

            var t = hint.Trim();
            if (t.StartsWith("IO: ", StringComparison.OrdinalIgnoreCase))
                t = t.Substring("IO: ".Length);

            var paren = t.IndexOf('(');
            if (paren >= 0)
                t = t.Substring(0, paren).Trim();

            if (t.Length > 42)
                t = t.Substring(0, 42) + "...";

            return t;
        }

        private sealed class LoopSummary
        {
            public uint Header;
            public readonly HashSet<uint> Latches = new HashSet<uint>();
            public string InductionVar;
            public int? Step;
            public string Bound;
            public string Cond;
        }

        private static void InferLoopsForFunction(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            List<uint> sortedBlockStarts,
            uint startAddr,
            uint endAddrExclusive,
            int startIdx,
            int endIdxExclusive,
            out List<LoopSummary> loops)
        {
            loops = new List<LoopSummary>();
            if (instructions == null || insIndexByAddr == null)
                return;
            if (startIdx < 0 || endIdxExclusive <= startIdx)
                return;

            var loopByHeader = new Dictionary<uint, LoopSummary>();

            // Back-edges: any branch/cjump to an earlier address within the same function.
            for (var i = startIdx; i < endIdxExclusive; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;
                if (addr < startAddr || addr >= endAddrExclusive)
                    continue;

                if (!TryGetRelativeBranchTarget(ins, out var target, out var isCall) || isCall)
                    continue;

                if (target < startAddr || target >= endAddrExclusive)
                    continue;

                if (target >= addr)
                    continue;

                if (!loopByHeader.TryGetValue(target, out var ls))
                    loopByHeader[target] = ls = new LoopSummary { Header = target };
                ls.Latches.Add(addr);
            }

            if (loopByHeader.Count == 0)
                return;

            // Helper: find the end of a basic block starting at blockStart.
            uint FindBlockEnd(uint blockStart)
            {
                if (sortedBlockStarts == null || sortedBlockStarts.Count == 0)
                    return endAddrExclusive;

                var idx = sortedBlockStarts.BinarySearch(blockStart);
                idx = idx < 0 ? ~idx : idx + 1;
                while (idx >= 0 && idx < sortedBlockStarts.Count)
                {
                    var b = sortedBlockStarts[idx];
                    if (b <= blockStart)
                    {
                        idx++;
                        continue;
                    }
                    if (b >= endAddrExclusive)
                        break;
                    return b;
                }

                return endAddrExclusive;
            }

            // Induction-var heuristic: look for cmp [local_X], imm near header and inc/add/sub/dec of same local near a latch.
            foreach (var kv in loopByHeader.OrderBy(k => k.Key).Take(8))
            {
                var ls = kv.Value;
                var headerStart = ls.Header;
                var headerEnd = FindBlockEnd(headerStart);
                if (!insIndexByAddr.TryGetValue(headerStart, out var headerIdx))
                    continue;

                var headerStopIdx = endIdxExclusive;
                if (insIndexByAddr.TryGetValue(headerEnd, out var he))
                    headerStopIdx = Math.Min(endIdxExclusive, he);

                string cmpVar = null;
                string cmpImm = null;
                string cmpCond = null;

                // Scan a small window at loop header.
                var scanHeaderMax = Math.Min(headerStopIdx, headerIdx + 24);
                for (var i = headerIdx; i < scanHeaderMax; i++)
                {
                    var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();
                    var mCmpMem = Regex.Match(cooked, @"^cmp\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                    var mCmpReg = Regex.Match(cooked, @"^cmp\s+(?<reg>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                    if (mCmpMem.Success)
                    {
                        cmpVar = mCmpMem.Groups["var"].Value;
                        cmpImm = mCmpMem.Groups["imm"].Value;
                    }
                    else if (mCmpReg.Success)
                    {
                        cmpVar = mCmpReg.Groups["reg"].Value.ToLowerInvariant();
                        cmpImm = mCmpReg.Groups["imm"].Value;
                    }
                    else
                    {
                        continue;
                    }

                    // Look ahead for the branch that uses this cmp.
                    for (var j = i + 1; j < Math.Min(scanHeaderMax, i + 4); j++)
                    {
                        var t = RewriteStackFrameOperands(InsText(instructions[j])).Trim();
                        var sp = t.IndexOf(' ');
                        var mn = (sp > 0 ? t.Substring(0, sp) : t).Trim().ToLowerInvariant();
                        if (!mn.StartsWith("j", StringComparison.OrdinalIgnoreCase) || mn == "jmp")
                            continue;
                        cmpCond = mn;
                        break;
                    }
                    break;
                }

                if (!string.IsNullOrWhiteSpace(cmpVar))
                {
                    // Scan latches for updates.
                    foreach (var latch in ls.Latches.OrderBy(x => x))
                    {
                        if (!insIndexByAddr.TryGetValue(latch, out var latchIdx))
                            continue;

                        var latchEnd = FindBlockEnd(latch);
                        var latchStopIdx = endIdxExclusive;
                        if (insIndexByAddr.TryGetValue(latchEnd, out var le))
                            latchStopIdx = Math.Min(endIdxExclusive, le);

                        var scanLatchMax = Math.Min(latchStopIdx, latchIdx + 20);
                        for (var i = latchIdx; i < scanLatchMax; i++)
                        {
                            var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();

                            if (cmpVar.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
                            {
                                if (Regex.IsMatch(cooked, $@"^inc\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = 1;
                                    break;
                                }
                                if (Regex.IsMatch(cooked, $@"^dec\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = -1;
                                    break;
                                }

                                var mAddMem = Regex.Match(cooked, $@"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[{Regex.Escape(cmpVar)}\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddMem.Success)
                                {
                                    if (TryParseHexOrDecUInt32(mAddMem.Groups["imm"].Value, out var u) && u <= 0x100)
                                    {
                                        var step = (int)u;
                                        if (mAddMem.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                            step = -step;
                                        ls.InductionVar = cmpVar;
                                        ls.Step = step;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                if (Regex.IsMatch(cooked, $@"^inc\s+{Regex.Escape(cmpVar)}\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = 1;
                                    break;
                                }
                                if (Regex.IsMatch(cooked, $@"^dec\s+{Regex.Escape(cmpVar)}\s*$", RegexOptions.IgnoreCase))
                                {
                                    ls.InductionVar = cmpVar;
                                    ls.Step = -1;
                                    break;
                                }

                                var mAddReg = Regex.Match(cooked, $@"^(?<op>add|sub)\s+{Regex.Escape(cmpVar)}\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddReg.Success)
                                {
                                    if (TryParseHexOrDecUInt32(mAddReg.Groups["imm"].Value, out var u) && u <= 0x100)
                                    {
                                        var step = (int)u;
                                        if (mAddReg.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                            step = -step;
                                        ls.InductionVar = cmpVar;
                                        ls.Step = step;
                                        break;
                                    }
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                                break;
                        }

                        if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                            break;
                    }

                    // Only keep header-derived bound/cond if it also gave us a matching induction update.
                    // Otherwise, it is likely an unrelated in-loop compare.
                    if (!string.IsNullOrWhiteSpace(ls.InductionVar))
                    {
                        ls.Bound = cmpImm;
                        ls.Cond = cmpCond;
                    }
                }

                // Countdown-loop heuristic: look for `dec/inc/add/sub` right before a back-edge jcc,
                // or x86 `loop/loope/loopne` which implies ECX-- and jump while ECX != 0.
                if (string.IsNullOrWhiteSpace(ls.InductionVar) || !ls.Step.HasValue)
                {
                    foreach (var latch in ls.Latches.OrderBy(x => x))
                    {
                        if (!insIndexByAddr.TryGetValue(latch, out var latchIdx))
                            continue;

                        var latchText = RewriteStackFrameOperands(InsText(instructions[latchIdx])).Trim();
                        var sp = latchText.IndexOf(' ');
                        var latchMn = (sp > 0 ? latchText.Substring(0, sp) : latchText).Trim().ToLowerInvariant();

                        // `loop` family
                        if (latchMn == "loop" || latchMn == "loope" || latchMn == "loopz" || latchMn == "loopne" || latchMn == "loopnz")
                        {
                            ls.InductionVar = "ecx";
                            ls.Step = -1;
                            ls.Bound ??= "0";
                            ls.Cond = latchMn;
                            break;
                        }

                        // For conditional branches, try to infer a counter update directly preceding.
                        if (latchMn.StartsWith("j", StringComparison.OrdinalIgnoreCase) && latchMn != "jmp")
                        {
                            // Prefer the actual latch condition.
                            ls.Cond = latchMn;

                            var isEqLatch = latchMn == "jnz" || latchMn == "jne" || latchMn == "jz" || latchMn == "je";

                            // If it's a jnz/jne style back-edge, common idiom is count-down to zero.
                            if ((latchMn == "jnz" || latchMn == "jne") && string.IsNullOrWhiteSpace(ls.Bound))
                                ls.Bound = "0";

                            // Only treat dec/inc/add/sub as a countdown/update hint for equality-style latches.
                            // For other jccs (e.g., jb/jae), the latch usually depends on a preceding cmp, not dec/inc.
                            if (!isEqLatch)
                            {
                                // Non-equality latch heuristic (safe): if the latch is fed by a nearby `cmp lhs, rhs`,
                                // and we see an update of `lhs` shortly before the cmp/jcc, treat `lhs` as the iv.
                                // This catches common idioms like:
                                //   inc edx
                                //   cmp edx, ecx
                                //   jb  header
                                // and avoids using unrelated dec/inc used for string ops unless it participates in cmp.

                                string cmpLhs = null;
                                string cmpRhs = null;
                                var cmpIdx = -1;

                                // Find the closest cmp in a small window before the latch.
                                for (var k = Math.Max(startIdx, latchIdx - 4); k < latchIdx; k++)
                                {
                                    var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();
                                    var mCmpReg = Regex.Match(prev, @"^cmp\s+(?<lhs>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<rhs>0x[0-9A-Fa-f]+|[0-9]+|e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                    var mCmpMem = Regex.Match(prev, @"^cmp\s+(?:byte|word|dword)?\s*\[(?<lhs>local_[0-9A-Fa-f]+)\]\s*,\s*(?<rhs>0x[0-9A-Fa-f]+|[0-9]+|e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                    if (mCmpReg.Success)
                                    {
                                        cmpLhs = mCmpReg.Groups["lhs"].Value.ToLowerInvariant();
                                        cmpRhs = mCmpReg.Groups["rhs"].Value.ToLowerInvariant();
                                        cmpIdx = k;
                                    }
                                    else if (mCmpMem.Success)
                                    {
                                        cmpLhs = mCmpMem.Groups["lhs"].Value;
                                        cmpRhs = mCmpMem.Groups["rhs"].Value.ToLowerInvariant();
                                        cmpIdx = k;
                                    }
                                }

                                if (!string.IsNullOrWhiteSpace(cmpLhs))
                                {
                                    // Find an update of cmpLhs shortly before the latch.
                                    // Prefer scanning before the cmp (not before the jcc), since some patterns have
                                    // setup work between the update and the cmp (e.g. string ops between inc and cmp).
                                    var updateStop = (cmpIdx >= 0 ? cmpIdx : latchIdx);
                                    for (var k = Math.Max(startIdx, updateStop - 12); k < updateStop; k++)
                                    {
                                        var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();

                                        if (cmpLhs.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
                                        {
                                            var esc = Regex.Escape(cmpLhs);
                                            if (Regex.IsMatch(prev, $@"^inc\s+(?:byte|word|dword)?\s*\[{esc}\]\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = 1;
                                                break;
                                            }
                                            if (Regex.IsMatch(prev, $@"^dec\s+(?:byte|word|dword)?\s*\[{esc}\]\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = -1;
                                                break;
                                            }

                                            var mAddMem2 = Regex.Match(prev, $@"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[{esc}\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                            if (mAddMem2.Success && TryParseHexOrDecUInt32(mAddMem2.Groups["imm"].Value, out var u3) && u3 <= 0x100)
                                            {
                                                var step = (int)u3;
                                                if (mAddMem2.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                                    step = -step;
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = step;
                                                break;
                                            }
                                        }
                                        else
                                        {
                                            var esc = Regex.Escape(cmpLhs);
                                            if (Regex.IsMatch(prev, $@"^inc\s+{esc}\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = 1;
                                                break;
                                            }
                                            if (Regex.IsMatch(prev, $@"^dec\s+{esc}\s*$", RegexOptions.IgnoreCase))
                                            {
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = -1;
                                                break;
                                            }

                                            var mAddReg2 = Regex.Match(prev, $@"^(?<op>add|sub)\s+{esc}\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                            if (mAddReg2.Success && TryParseHexOrDecUInt32(mAddReg2.Groups["imm"].Value, out var u4) && u4 <= 0x100)
                                            {
                                                var step = (int)u4;
                                                if (mAddReg2.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                                    step = -step;
                                                ls.InductionVar = cmpLhs;
                                                ls.Step = step;
                                                break;
                                            }
                                        }
                                    }

                                    if (!string.IsNullOrWhiteSpace(ls.InductionVar) && ls.Step.HasValue)
                                    {
                                        if (string.IsNullOrWhiteSpace(ls.Bound) && !string.IsNullOrWhiteSpace(cmpRhs))
                                            ls.Bound = cmpRhs;
                                        break;
                                    }
                                }

                                continue;
                            }

                            for (var k = Math.Max(startIdx, latchIdx - 3); k < latchIdx; k++)
                            {
                                var prev = RewriteStackFrameOperands(InsText(instructions[k])).Trim();

                                // dec/inc reg
                                var mDecReg = Regex.Match(prev, @"^(?<op>dec|inc)\s+(?<reg>e?(ax|bx|cx|dx|si|di|bp|sp))\s*$", RegexOptions.IgnoreCase);
                                if (mDecReg.Success)
                                {
                                    var reg = mDecReg.Groups["reg"].Value.ToLowerInvariant();
                                    var op = mDecReg.Groups["op"].Value.ToLowerInvariant();
                                    ls.InductionVar = reg;
                                    ls.Step = op == "dec" ? -1 : 1;
                                    break;
                                }

                                // dec/inc [local]
                                var mDecMem = Regex.Match(prev, @"^(?<op>dec|inc)\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
                                if (mDecMem.Success)
                                {
                                    var v = mDecMem.Groups["var"].Value;
                                    var op = mDecMem.Groups["op"].Value.ToLowerInvariant();
                                    ls.InductionVar = v;
                                    ls.Step = op == "dec" ? -1 : 1;
                                    break;
                                }

                                // add/sub reg, imm or add/sub [local], imm
                                var mAddReg = Regex.Match(prev, @"^(?<op>add|sub)\s+(?<dst>e?(ax|bx|cx|dx|si|di|bp|sp))\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddReg.Success && TryParseHexOrDecUInt32(mAddReg.Groups["imm"].Value, out var u1) && u1 <= 0x100)
                                {
                                    var dst = mAddReg.Groups["dst"].Value.ToLowerInvariant();
                                    var step = (int)u1;
                                    if (mAddReg.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                        step = -step;
                                    ls.InductionVar = dst;
                                    ls.Step = step;
                                    break;
                                }

                                var mAddMem = Regex.Match(prev, @"^(?<op>add|sub)\s+(?:byte|word|dword)?\s*\[(?<var>local_[0-9A-Fa-f]+)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                                if (mAddMem.Success && TryParseHexOrDecUInt32(mAddMem.Groups["imm"].Value, out var u2) && u2 <= 0x100)
                                {
                                    var dst = mAddMem.Groups["var"].Value;
                                    var step = (int)u2;
                                    if (mAddMem.Groups["op"].Value.Equals("sub", StringComparison.OrdinalIgnoreCase))
                                        step = -step;
                                    ls.InductionVar = dst;
                                    ls.Step = step;
                                    break;
                                }
                            }

                            if (!string.IsNullOrWhiteSpace(ls.InductionVar) && ls.Step.HasValue)
                                break;
                        }
                    }
                }

                loops.Add(ls);
            }
        }

        private static string FormatLoopSummaryForFunction(List<LoopSummary> loops)
        {
            if (loops == null || loops.Count == 0)
                return string.Empty;

            var parts = new List<string>();
            var idx = 0;
            foreach (var l in loops.Take(3))
            {
                // Keep the first loop detailed; subsequent loops are compact to avoid line wrap.
                var latch = (idx == 0 && l.Latches.Count > 0) ? $" latch=0x{l.Latches.Min():X8}" : string.Empty;
                var iv = (idx == 0 && !string.IsNullOrWhiteSpace(l.InductionVar)) ? $" iv={l.InductionVar}" : string.Empty;
                var step = (idx == 0 && l.Step.HasValue) ? $" step={(l.Step.Value >= 0 ? "+" : string.Empty)}{l.Step.Value}" : string.Empty;
                var bound = !string.IsNullOrWhiteSpace(l.Bound) ? $" bound={l.Bound}" : string.Empty;
                var cond = !string.IsNullOrWhiteSpace(l.Cond) ? $" cond={l.Cond}" : string.Empty;
                parts.Add($"hdr=0x{l.Header:X8}{latch}{iv}{step}{bound}{cond}");
                idx++;
            }

            var more = loops.Count > 3 ? $", ... (+{loops.Count - 3})" : string.Empty;
            return $"LOOPS: {string.Join(", ", parts)}{more}";
        }

        private static string FormatLoopHeaderHint(LoopSummary loop)
        {
            if (loop == null)
                return string.Empty;

            var latch = loop.Latches.Count > 0 ? $"latch=0x{loop.Latches.Min():X8}" : string.Empty;
            var iv = !string.IsNullOrWhiteSpace(loop.InductionVar) ? $"iv={loop.InductionVar}" : string.Empty;
            var step = loop.Step.HasValue ? $"step={(loop.Step.Value >= 0 ? "+" : string.Empty)}{loop.Step.Value}" : string.Empty;
            var bound = !string.IsNullOrWhiteSpace(loop.Bound) ? $"bound={loop.Bound}" : string.Empty;
            var cond = !string.IsNullOrWhiteSpace(loop.Cond) ? $"cond={loop.Cond}" : string.Empty;
            var parts = new[] { latch, iv, step, bound, cond }.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
            return parts.Count == 0 ? "LOOPHDR" : $"LOOPHDR: {string.Join(" ", parts)}";
        }

        private static string InferPointerishArgSummaryForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive)
        {
            if (instructions == null || startIdx < 0 || endIdxExclusive <= startIdx)
                return string.Empty;

            var ptrArgs = new HashSet<int>();
            var regSource = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(instructions.Count, endIdxExclusive);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i])).Trim();

                // Far-pointer loads: lgs/les/lfs reg, [arg_N]
                var fp = Regex.Match(cooked, @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>arg_(?<idx>[0-9]+))\]\s*$", RegexOptions.IgnoreCase);
                if (fp.Success && int.TryParse(fp.Groups["idx"].Value, out var fpIdx))
                    ptrArgs.Add(fpIdx);

                // Track reg <- [arg_N]
                var m = Regex.Match(cooked, @"^mov\s+(?<reg>e[a-z]{2})\s*,\s*\[arg_(?<idx>[0-9]+)\]\s*$", RegexOptions.IgnoreCase);
                if (m.Success && int.TryParse(m.Groups["idx"].Value, out var argIdx))
                {
                    regSource[m.Groups["reg"].Value.ToLowerInvariant()] = argIdx;
                    continue;
                }

                foreach (var kv in regSource.ToList())
                {
                    var reg = kv.Key;
                    var srcIdx = kv.Value;
                    if (InsTextUsesRegAsMemBase(cooked, reg))
                        ptrArgs.Add(srcIdx);
                    if (InstructionWritesReg(cooked, reg))
                        regSource.Remove(reg);
                }
            }

            if (ptrArgs.Count == 0)
                return string.Empty;

            var shown = ptrArgs.OrderBy(x => x).Take(8).Select(x => $"ptr_arg_{x}").ToList();
            var more = ptrArgs.Count > 8 ? $", ... (+{ptrArgs.Count - 8})" : string.Empty;
            return string.Join(", ", shown) + more;
        }

        private static string CollectInterruptSummaryForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdxExclusive,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex)
        {
            if (instructions == null || startIdx < 0 || endIdxExclusive <= startIdx)
                return string.Empty;

            var uniq = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ordered = new List<string>();
            var max = Math.Min(instructions.Count, endIdxExclusive);
            for (var i = startIdx; i < max; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (!t.StartsWith("int ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var hint = TryAnnotateInterrupt(instructions, i, stringSymbols, stringPreview, objects, objBytesByIndex);
                var shortHint = ShortenInterruptHintForCase(hint);
                if (string.IsNullOrWhiteSpace(shortHint))
                    continue;
                if (uniq.Add(shortHint))
                    ordered.Add(shortHint);
                if (ordered.Count >= 6)
                    break;
            }

            if (ordered.Count == 0)
                return string.Empty;
            return string.Join(", ", ordered);
        }

        private static string FormatCSketchHeader(
            uint startAddr,
            string protoHint,
            Dictionary<string, string> outLocalAliases,
            Dictionary<string, int> localBitWidths,
            string ptrArgSummary,
            FunctionSummary summary,
            string ioSummary,
            string intSummary,
            string loopSummary)
        {
            static string CapCommaSummary(string summary, int maxItems, int maxLen)
            {
                if (string.IsNullOrWhiteSpace(summary))
                    return string.Empty;

                var s = summary.Trim();
                var items = s.Split(new[] { ", " }, StringSplitOptions.None)
                    .Select(x => x.Trim())
                    .Where(x => x.Length > 0)
                    .ToList();

                if (items.Count > maxItems)
                    s = string.Join(", ", items.Take(maxItems)) + ",...";
                else
                    s = string.Join(", ", items);

                if (maxLen > 16 && s.Length > maxLen)
                    s = s.Substring(0, maxLen - 3).TrimEnd() + "...";

                return s;
            }

            var parts = new List<string>();

            if (!string.IsNullOrWhiteSpace(protoHint))
            {
                var p = protoHint.Trim();
                if (p.StartsWith("PROTO:", StringComparison.OrdinalIgnoreCase))
                    p = p.Substring("PROTO:".Length).Trim();
                var semi = p.IndexOf(';');
                if (semi >= 0)
                    p = p.Substring(0, semi).Trim();
                parts.Add($"proto={p}");
            }
            else
            {
                    parts.Add($"proto=func_{startAddr:X8}()");
            }

            // Prioritize reconstructability: out-params + pointer-ish args + loops.
            var hasStrongSignals = false;
            if (outLocalAliases != null && outLocalAliases.Count > 0)
            {
                var vals = new List<string>();
                foreach (var kv in outLocalAliases.OrderBy(k => k.Key).Take(8))
                {
                    var alias = kv.Value;
                    if (localBitWidths != null && localBitWidths.TryGetValue(kv.Key, out var bits))
                        alias = UpgradeOutpAliasWithBitWidth(alias, bits);
                    if (!string.IsNullOrWhiteSpace(alias))
                        vals.Add(alias);
                }
                if (vals.Count > 0)
                {
                    parts.Add($"out={string.Join(",", vals)}");
                    hasStrongSignals = true;
                }
            }

            if (!string.IsNullOrWhiteSpace(ptrArgSummary))
            {
                parts.Add($"args={ptrArgSummary}");
                hasStrongSignals = true;
            }

            var intShort = CapCommaSummary(intSummary, maxItems: 1, maxLen: 70);
            if (!string.IsNullOrWhiteSpace(intShort))
            {
                parts.Add($"int={intShort}");
                hasStrongSignals = true;
            }

            var ioShort = CapCommaSummary(ioSummary, maxItems: 1, maxLen: 70);
            if (!string.IsNullOrWhiteSpace(ioShort))
            {
                parts.Add($"io={ioShort}");
                hasStrongSignals = true;
            }

            if (summary != null)
            {
                var hasGlobals = summary.Globals != null && summary.Globals.Count > 0;
                if (hasGlobals)
                    parts.Add($"globals={string.Join(",", summary.Globals.OrderBy(x => x).Take(3))}{(summary.Globals.Count > 3 ? ",..." : string.Empty)}");

                if (!hasStrongSignals && !hasGlobals && summary.Strings != null && summary.Strings.Count > 0)
                    parts.Add($"strings={string.Join(",", summary.Strings.OrderBy(x => x).Take(2))}{(summary.Strings.Count > 2 ? ",..." : string.Empty)}");
            }

            if (!string.IsNullOrWhiteSpace(loopSummary))
            {
                parts.Add(loopSummary);
                hasStrongSignals = true;
            }

            return parts.Count == 0 ? string.Empty : $"C: {string.Join(" | ", parts)}";
        }

        private static string TrySummarizeCaseTargetRole(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            uint targetAddr,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex)
        {
            if (instructions == null || insIndexByAddr == null)
                return string.Empty;
            if (!insIndexByAddr.TryGetValue(targetAddr, out var idx))
                return string.Empty;

            ushort? localDxImm16 = null;
            string localDxSource = null;
            byte? localAlImm8 = null;
            ushort? localAxImm16 = null;
            var localNotes = new List<string>();

            var max = Math.Min(instructions.Count, idx + 28);
            for (var i = idx; i < max; i++)
            {
                var raw = InsText(instructions[i]);
                var cooked = RewriteStackFrameOperands(raw);

                // Lightweight local/flag setup detection (common in switch case handlers).
                if (localNotes.Count < 2 && (i - idx) <= 8)
                {
                    var mMov = Regex.Match(cooked, @"^\s*mov\s+(?:byte|word|dword)\s+\[(?<mem>local_[0-9A-Fa-f]+|g_[0-9A-Fa-f]{8})\]\s*,\s*(?<imm>(?:0x)?[0-9A-Fa-f]+)h?\s*$", RegexOptions.IgnoreCase);
                    if (mMov.Success)
                    {
                        var mem = mMov.Groups["mem"].Value;
                        var imm = mMov.Groups["imm"].Value;
                        if (TryParseHexOrDecUInt32(imm, out var v))
                            localNotes.Add($"set {mem}=0x{v:X}");
                    }

                    if (localNotes.Count < 2)
                    {
                        var mLea = Regex.Match(cooked, @"^\s*lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<mem>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
                        if (mLea.Success)
                        {
                            var reg = mLea.Groups["reg"].Value.ToLowerInvariant();
                            var mem = mLea.Groups["mem"].Value;
                            localNotes.Add($"{reg}=&{mem}");
                        }
                    }
                }

                // Prefer "strong" actions first.
                var intHint = TryAnnotateInterrupt(instructions, i, stringSymbols, stringPreview, objects, objBytesByIndex);
                if (!string.IsNullOrEmpty(intHint))
                {
                    var shortInt = ShortenInterruptHintForCase(intHint);
                    return string.IsNullOrEmpty(shortInt) ? string.Empty : $"INT {shortInt}";
                }

                if (TryParseMovDxImmediate(cooked, out var dxImm))
                {
                    localDxImm16 = dxImm;
                    localDxSource = $"0x{dxImm:X4}";
                }

                if (TryParseMovDxFromMemory(cooked, out var dxMem))
                {
                    localDxImm16 = null;
                    localDxSource = $"[{dxMem}]";
                }

                if (TryParseMovAlImmediate(cooked, out var alImm))
                    localAlImm8 = alImm;
                if (TryParseMovAxImmediate(cooked, out var axImm))
                    localAxImm16 = axImm;

                var ioHint = TryAnnotateIoPortAccess(cooked, localDxImm16, localDxSource, localAlImm8, localAxImm16);
                if (!string.IsNullOrEmpty(ioHint))
                {
                    var shortIo = ShortenIoHintForCase(ioHint);
                    return string.IsNullOrEmpty(shortIo) ? string.Empty : $"IO {shortIo}";
                }

                // Don't scan past an obvious terminal for this tiny summary.
                var t = cooked.TrimStart();
                if (t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp ", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            if (localNotes.Count > 0)
                return string.Join(", ", localNotes);

            return string.Empty;
        }

        private static string TryAnnotateByteSwitchDecisionTree(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int startIdx,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> stringPreview,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            out string signature,
            out Dictionary<string, string> inferredLocalAliases,
            out List<string> localAliasHints)
        {
            // Recognize compiler-generated decision trees for switch/case on a byte register.
            // Typical shape: cmp al, imm ; jz loc_case ; ... ; unconditional jmp loc_default
            signature = null;
            inferredLocalAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            localAliasHints = new List<string>();
            if (instructions == null || startIdx < 0 || startIdx >= instructions.Count)
                return string.Empty;

            // Guard: only annotate at decision-tree nodes that actually start with the canonical compare.
            if (!TryParseCmpReg8Imm8(InsText(instructions[startIdx]), out _, out _))
                return string.Empty;

            // First, try to stabilize the "chain start" by scanning backwards for nearby cmp+je patterns.
            // This keeps the signature consistent even if we emit at bb_ labels mid-chain.
            const int backWindow = 256;
            const int forwardWindow = 256;

            var backLimit = Math.Max(0, startIdx - backWindow);
            var chainStart = startIdx;
            string chainReg = null;
            for (var i = startIdx; i >= backLimit; i--)
            {
                if (i + 1 >= instructions.Count)
                    continue;

                var a = InsText(instructions[i]);
                if (!TryParseCmpReg8Imm8(a, out var r8, out _))
                    continue;

                if (!IsEqualityJumpMnemonic(InsText(instructions[i + 1])))
                    continue;

                if (chainReg == null)
                    chainReg = r8;
                else if (!chainReg.Equals(r8, StringComparison.OrdinalIgnoreCase))
                    continue;

                chainStart = i;
            }

            var maxScan = Math.Min(instructions.Count, chainStart + forwardWindow);

            // Collect equality tests for a single reg8.
            var reg = chainReg;
            var cases = new Dictionary<byte, uint>();

            for (var i = chainStart; i + 1 < maxScan; i++)
            {
                var a = InsText(instructions[i]);
                if (!TryParseCmpReg8Imm8(a, out var r8, out var imm8))
                    continue;

                if (reg == null)
                    reg = r8;
                else if (!reg.Equals(r8, StringComparison.OrdinalIgnoreCase))
                    continue;

                var b = instructions[i + 1];
                if (!IsEqualityJumpMnemonic(InsText(b)))
                    continue;

                if (TryGetRelativeBranchTarget(b, out var target, out var isCall) && !isCall)
                {
                    if (!cases.ContainsKey(imm8))
                        cases[imm8] = (uint)target;
                }
            }

            if (string.IsNullOrEmpty(reg) || cases.Count < 4)
                return string.Empty;

            signature = reg + "|" + string.Join(",", cases.OrderBy(k => k.Key).Select(k => $"{k.Key:X2}->{k.Value:X8}"));

            // Best-effort interpretation: if this is predominantly printable ASCII cases, it's probably token/command dispatch.
            var printable = cases.Keys.Count(b => b >= 0x20 && b <= 0x7E);
            var maybeAsciiDispatch = printable >= 4 && (printable * 1.0 / cases.Count) >= 0.75;
            var maybeTokenChar = maybeAsciiDispatch && cases.Keys.Any(b => b == 0x20 || b == (byte)'-' || b == (byte)'/' || b == (byte)'.' || b == (byte)'_');
            var kind = maybeTokenChar
                ? "ASCII dispatch (likely token/command char)"
                : (maybeAsciiDispatch ? "ASCII dispatch" : string.Empty);

            // Compute per-case roles first, then infer local aliases, then render using the aliases.
            var roleByCase = new Dictionary<byte, string>();
            foreach (var kv in cases)
            {
                var role = TrySummarizeCaseTargetRole(instructions, insIndexByAddr, kv.Value, stringSymbols, stringPreview, objects, objBytesByIndex);
                if (!string.IsNullOrEmpty(role))
                    roleByCase[kv.Key] = role;
            }

            InferLocalAliasesFromSwitchCases(roleByCase, out inferredLocalAliases, out localAliasHints);

            // Don't capture the out-parameter in lambdas.
            var inferredAliases = inferredLocalAliases;

            var parts = cases
                .OrderBy(k => k.Key)
                .Take(10)
                .Select(k =>
                {
                    var ch = FormatImm8AsChar(k.Key);
                    var imm = !string.IsNullOrEmpty(ch) ? $"{ch} (0x{k.Key:X2})" : $"0x{k.Key:X2}";
                    roleByCase.TryGetValue(k.Key, out var role);
                    if (!string.IsNullOrEmpty(role))
                    {
                        role = RewriteLocalAliasTokens(role, inferredAliases);
                        return $"{imm}->loc_{k.Value:X8} ({role})";
                    }
                    return $"{imm}->loc_{k.Value:X8}";
                })
                .ToList();

            var more = cases.Count > 10 ? $", ... (+{cases.Count - 10})" : string.Empty;
            var kindSuffix = string.IsNullOrEmpty(kind) ? string.Empty : $" {kind}:";
            return $"BBHINT: switch({reg}) decision tree{kindSuffix} {string.Join(", ", parts)}{more}";
        }

        private static string RewriteStackFrameOperands(string insText)
        {
            if (string.IsNullOrEmpty(insText))
                return insText;

            // Best-effort: rewrite [ebp +/- 0xNN] to [arg_N]/[local_NN]
            // Assumes typical 32-bit stack frame: [ebp+8] is arg0.
            return EbpDispRegex.Replace(insText, m =>
            {
                var sign = m.Groups["sign"].Value;
                var hex = m.Groups["hex"].Value;
                if (!TryParseHexUInt(hex, out var off))
                    return m.Value;

                if (sign == "-")
                {
                    // locals grow downward
                    return $"[local_{off:X}]";
                }

                // args: ebp+8 is first arg
                if (off >= 8 && (off - 8) % 4 == 0)
                {
                    var argIndex = (off - 8) / 4;
                    return $"[arg_{argIndex}]";
                }

                return m.Value;
            });
        }

        private static string RewriteLocalAliasTokens(string text, Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrEmpty(text) || localAliases == null || localAliases.Count == 0)
                return text;

            return Regex.Replace(text, @"\blocal_[0-9A-Fa-f]+\b", m =>
            {
                var key = m.Value;
                if (localAliases.TryGetValue(key, out var alias) && !string.IsNullOrWhiteSpace(alias))
                    return alias;
                return key;
            });
        }

        private sealed class LocalAliasEvidence
        {
            public readonly HashSet<byte> Cases = new HashSet<byte>();
            public readonly HashSet<uint> Values = new HashSet<uint>();
            public bool AddressTaken;
        }

        private static bool TryParseRoleNoteSetLocal(string note, out string localName, out uint value)
        {
            localName = null;
            value = 0;
            if (string.IsNullOrWhiteSpace(note))
                return false;

            // Example: "set local_1C=0x1"
            var m = Regex.Match(note.Trim(), @"^set\s+(?<local>local_[0-9A-Fa-f]+)\s*=\s*(?<imm>0x[0-9A-Fa-f]+|[0-9]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            localName = m.Groups["local"].Value;
            var imm = m.Groups["imm"].Value;
            if (!TryParseHexOrDecUInt32(imm, out var v))
                return false;
            value = v;
            return true;
        }

        private static bool TryParseRoleNoteAddrTaken(string note, out string localName)
        {
            localName = null;
            if (string.IsNullOrWhiteSpace(note))
                return false;

            // Example: "edx=&local_14"
            var m = Regex.Match(note.Trim(), @"^(?<reg>e[a-z]{2})\s*=\s*&(?<local>local_[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            localName = m.Groups["local"].Value;
            return true;
        }

        private static bool IsSafeAliasIdent(string s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return false;
            return Regex.IsMatch(s, @"^[A-Za-z_][A-Za-z0-9_]*$");
        }

        private static string MakeOutpAliasFromLocal(string localName)
        {
            if (string.IsNullOrWhiteSpace(localName))
                return null;

            // local_14 -> outp_14
            var m = Regex.Match(localName, @"^local_(?<hex>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return null;

            return "outp_" + m.Groups["hex"].Value.ToUpperInvariant();
        }

        private static bool TryParseLeaRegOfLocal(string insText, out string reg, out string localName)
        {
            reg = null;
            localName = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Example: "lea edx, [local_14]"
            var m = Regex.Match(insText.Trim(), @"^lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<mem>local_[0-9A-Fa-f]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            localName = m.Groups["mem"].Value;
            return true;
        }

        private static bool TryParsePushReg(string insText, out string reg)
        {
            reg = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;
            var m = Regex.Match(insText.Trim(), @"^push\s+(?<reg>e[a-z]{2})\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;
            reg = m.Groups["reg"].Value.ToLowerInvariant();
            return true;
        }

        private static bool InstructionWritesReg(string insText, string reg)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // Reuse existing coarse matcher.
            var m = WritesRegRegex.Match(insText.Trim());
            if (!m.Success)
                return false;
            return m.Groups["dst"].Value.Equals(reg, StringComparison.OrdinalIgnoreCase);
        }

        private static int? GetRegBitWidth(string reg)
        {
            if (string.IsNullOrWhiteSpace(reg))
                return null;

            reg = reg.Trim().ToLowerInvariant();
            if (reg.Length == 3 && reg[0] == 'e')
                return 32;

            // 16-bit
            if (reg is "ax" or "bx" or "cx" or "dx" or "si" or "di" or "bp" or "sp")
                return 16;

            // 8-bit
            if (reg is "al" or "ah" or "bl" or "bh" or "cl" or "ch" or "dl" or "dh")
                return 8;

            return null;
        }

        private static void MergeBitWidthHint(Dictionary<string, int> bitsByToken, string token, int bits)
        {
            if (bitsByToken == null || string.IsNullOrWhiteSpace(token) || bits <= 0)
                return;

            if (bitsByToken.TryGetValue(token, out var prev))
                bitsByToken[token] = Math.Max(prev, bits);
            else
                bitsByToken[token] = bits;
        }

        private static void CollectLocalBitWidthHintsForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, int> bitsByLocal)
        {
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
                var t = cooked.Trim();

                // mov [local_XX], reg
                var m = Regex.Match(t, @"^mov\s+\[(?<local>local_[0-9A-Fa-f]+)\]\s*,\s*(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\b", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // mov reg, [local_XX]
                m = Regex.Match(t, @"^mov\s+(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\s*,\s*\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // explicit-sized mem ops (byte/word/dword/qword/tword)
                m = Regex.Match(t, @"\b(?<sz>byte|word|dword|qword|tword)\s+\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var sz = m.Groups["sz"].Value.ToLowerInvariant();
                    var bits = sz switch
                    {
                        "byte" => 8,
                        "word" => 16,
                        "dword" => 32,
                        "qword" => 64,
                        "tword" => 80,
                        _ => 0
                    };
                    if (bits > 0)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits);
                    continue;
                }
            }
        }

        private static void CollectLocalBitWidthHintsForFunction(
            string[] cookedByIndex,
            int startIdx,
            int endIdx,
            out Dictionary<string, int> bitsByLocal)
        {
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (cookedByIndex == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(cookedByIndex.Length, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i] ?? string.Empty;
                var t = cooked.Trim();

                // mov [local_XX], reg
                var m = Regex.Match(t, @"^mov\s+\[(?<local>local_[0-9A-Fa-f]+)\]\s*,\s*(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\b", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // mov reg, [local_XX]
                m = Regex.Match(t, @"^mov\s+(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\s*,\s*\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    continue;
                }

                // explicit-sized mem ops (byte/word/dword/qword/tword)
                m = Regex.Match(t, @"\b(?<sz>byte|word|dword|qword|tword)\s+\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var sz = m.Groups["sz"].Value.ToLowerInvariant();
                    var bits = sz switch
                    {
                        "byte" => 8,
                        "word" => 16,
                        "dword" => 32,
                        "qword" => 64,
                        "tword" => 80,
                        _ => 0
                    };
                    if (bits > 0)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits);
                    continue;
                }
            }
        }

        private static string UpgradeOutpAliasWithBitWidth(string alias, int bits)
        {
            if (string.IsNullOrWhiteSpace(alias))
                return alias;

            // outp_14 -> outp16_14, etc.
            var m = Regex.Match(alias, @"^outp_(?<hex>[0-9A-Fa-f]+)$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return alias;

            var suffix = m.Groups["hex"].Value.ToUpperInvariant();
            return bits switch
            {
                8 => $"outp8_{suffix}",
                16 => $"outp16_{suffix}",
                32 => $"outp32_{suffix}",
                64 => $"outp64_{suffix}",
                80 => $"outp80_{suffix}",
                _ => alias
            };
        }

        private static string FormatProtoArgs(int argCount, int maxArgs)
        {
            if (argCount <= 0)
                return string.Empty;
            if (maxArgs <= 0)
                maxArgs = 12;

            var shown = Math.Min(argCount, maxArgs);
            var args = string.Join(", ", Enumerable.Range(0, shown).Select(x => $"arg_{x}"));
            if (shown < argCount)
                args += $", ... (+{argCount - shown})";
            return args;
        }

        private static bool TryParseMovRegFromTokenMem(string insText, out string reg, out string token)
        {
            reg = null;
            token = null;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples: "mov eax, [arg_0]", "mov edx, [local_20]"
            var m = Regex.Match(insText.Trim(), @"^mov\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            token = m.Groups["tok"].Value;
            return true;
        }

        private static bool InsTextUsesRegAsMemBase(string insText, string reg)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // Any memory operand like [reg] or [reg+...] etc.
            return Regex.IsMatch(insText, $@"\[(?:[^\]]*\b{Regex.Escape(reg)}\b[^\]]*)\]", RegexOptions.IgnoreCase);
        }

        private static bool LooksLikeFunctionFrameSetup(List<Instruction> instructions, int idx)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return false;

            var t = InsText(instructions[idx]).Trim();

            // Classic: push ebp; mov ebp, esp
            if (t.Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase))
            {
                var back = Math.Max(0, idx - 4);
                for (var i = back; i < idx; i++)
                {
                    if (InsText(instructions[i]).Trim().Equals("push ebp", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            // Less common, but still a clear frame setup.
            if (t.StartsWith("enter ", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        internal static int RefineFunctionStartsByPrologAfterRet(List<Instruction> instructions, HashSet<uint> functionStarts)
        {
            if (instructions == null || instructions.Count < 4 || functionStarts == null)
                return 0;

            static bool IsPadding(string t)
            {
                if (string.IsNullOrWhiteSpace(t))
                    return false;
                t = t.Trim();
                return t.Equals("nop", StringComparison.OrdinalIgnoreCase)
                    || t.Equals("int3", StringComparison.OrdinalIgnoreCase);
            }

            static bool IsRet(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().StartsWith("ret", StringComparison.OrdinalIgnoreCase);

            static bool IsPushEbp(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().Equals("push ebp", StringComparison.OrdinalIgnoreCase);

            static bool IsMovEbpEsp(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase);

            static bool IsEnter(string t)
                => !string.IsNullOrWhiteSpace(t) && t.Trim().StartsWith("enter ", StringComparison.OrdinalIgnoreCase);

            var added = 0;
            for (var i = 0; i < instructions.Count - 1; i++)
            {
                var ti = InsText(instructions[i]);
                if (!IsRet(ti))
                    continue;

                var j = i + 1;
                while (j < instructions.Count)
                {
                    var tj = InsText(instructions[j]);
                    if (!IsPadding(tj))
                        break;
                    j++;
                }

                if (j >= instructions.Count)
                    break;

                var t0 = InsText(instructions[j]);
                uint start = 0;
                var ok = false;

                if (IsEnter(t0))
                {
                    start = (uint)instructions[j].Offset;
                    ok = true;
                }
                else if (IsPushEbp(t0) && j + 1 < instructions.Count)
                {
                    var t1 = InsText(instructions[j + 1]);
                    if (IsMovEbpEsp(t1))
                    {
                        start = (uint)instructions[j].Offset;
                        ok = true;
                    }
                }

                if (!ok)
                    continue;

                if (!functionStarts.Contains(start))
                {
                    functionStarts.Add(start);
                    added++;
                }
            }

            return added;
        }

        private static void InferPointerishTokensForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out HashSet<string> pointerTokens)
        {
            pointerTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Tracks reg <- [arg/local], and marks that source as pointer-ish if the reg is later used as a memory base.
            var regSource = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));

                // Far-pointer loads imply the argument/local represents a pointer value (ES:reg etc).
                // Examples: "les edi, [arg_1]", "lgs eax, [arg_3]".
                var fp = Regex.Match(cooked.Trim(), @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\b", RegexOptions.IgnoreCase);
                if (fp.Success)
                    pointerTokens.Add(fp.Groups["tok"].Value);

                if (TryParseMovRegFromTokenMem(cooked, out var dstReg, out var tok))
                    regSource[dstReg] = tok;

                foreach (var kv in regSource.ToList())
                {
                    var reg = kv.Key;
                    var src = kv.Value;

                    if (InsTextUsesRegAsMemBase(cooked, reg))
                        pointerTokens.Add(src);

                    if (InstructionWritesReg(cooked, reg))
                        regSource.Remove(reg);
                }
            }
        }

        private static string RewriteArgAliasTokens(string text, Dictionary<string, string> argAliases)
        {
            if (string.IsNullOrEmpty(text) || argAliases == null || argAliases.Count == 0)
                return text;

            return Regex.Replace(text, @"\barg_[0-9]+\b", m =>
            {
                var key = m.Value;
                if (argAliases.TryGetValue(key, out var alias) && !string.IsNullOrWhiteSpace(alias))
                    return alias;
                return key;
            }, RegexOptions.IgnoreCase);
        }

        private static void ApplyPointerAliasForToken(string token, Dictionary<string, string> argAliases, Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrWhiteSpace(token))
                return;

            if (token.StartsWith("arg_", StringComparison.OrdinalIgnoreCase))
            {
                if (argAliases != null && !argAliases.ContainsKey(token))
                    argAliases[token] = "ptr_" + token;
                return;
            }

            if (token.StartsWith("local_", StringComparison.OrdinalIgnoreCase))
            {
                if (localAliases == null)
                    return;

                if (localAliases.TryGetValue(token, out var existing) && !string.IsNullOrWhiteSpace(existing))
                {
                    if (!existing.StartsWith("opt_", StringComparison.OrdinalIgnoreCase) && !existing.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase))
                        localAliases[token] = "ptr_" + existing;
                }
                else
                {
                    localAliases[token] = "ptr_" + token;
                }
            }
        }

        private static void UpdatePointerishTokenAliases(
            string insText,
            Dictionary<string, string> regSources,
            Dictionary<string, string> argAliases,
            Dictionary<string, string> localAliases)
        {
            if (string.IsNullOrWhiteSpace(insText))
                return;

            // Far-pointer loads imply the operand token represents a pointer value.
            var fp = Regex.Match(insText.Trim(), @"^(?<op>les|lfs|lgs)\s+\w+\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (fp.Success)
                ApplyPointerAliasForToken(fp.Groups["tok"].Value, argAliases, localAliases);

            // Track reg <- &arg/local
            var lea = Regex.Match(insText.Trim(), @"^lea\s+(?<reg>e[a-z]{2})\s*,\s*\[(?<tok>(arg_[0-9]+|local_[0-9A-Fa-f]+))\]\s*$", RegexOptions.IgnoreCase);
            if (lea.Success)
                regSources[lea.Groups["reg"].Value.ToLowerInvariant()] = lea.Groups["tok"].Value;

            // Track reg <- [arg/local]
            if (TryParseMovRegFromTokenMem(insText, out var dstReg, out var tok))
                regSources[dstReg] = tok;

            // If a tracked reg is used as a memory base, mark its source token pointer-ish.
            foreach (var kv in regSources.ToList())
            {
                var reg = kv.Key;
                var src = kv.Value;
                if (InsTextUsesRegAsMemBase(insText, reg))
                    ApplyPointerAliasForToken(src, argAliases, localAliases);

                if (InstructionWritesReg(insText, reg))
                    regSources.Remove(reg);
            }
        }

        private static void InferOutParamLocalAliasesForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Track most recent address-taken locals per register.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var raw = InsText(instructions[i]);
                var cooked = RewriteStackFrameOperands(raw);

                if (TryParseLeaRegOfLocal(cooked, out var leaReg, out var localName))
                {
                    lastLeaLocalByReg[leaReg] = (localName, i);
                    continue;
                }

                // Invalidate reg->local if the reg is overwritten.
                foreach (var k in lastLeaLocalByReg.Keys.ToList())
                {
                    if (InstructionWritesReg(cooked, k))
                        lastLeaLocalByReg.Remove(k);
                }

                var t = cooked.TrimStart();
                if (!t.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                    continue;

                // Heuristic: if we have a recent lea reg,[local] and either:
                // - the reg was pushed as an arg, or
                // - the lea is close enough to the call and reg wasn't overwritten
                // then the local is likely an out-parameter / by-ref temp.

                var pushedRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var back = Math.Max(startIdx, i - 10);
                for (var j = back; j < i; j++)
                {
                    var prev = RewriteStackFrameOperands(InsText(instructions[j]));
                    if (TryParsePushReg(prev, out var pr))
                        pushedRegs.Add(pr);
                }

                foreach (var kv in lastLeaLocalByReg.ToList())
                {
                    var reg = kv.Key;
                    var (loc, leaIdx) = kv.Value;

                    if ((i - leaIdx) > 8)
                        continue;

                    var isPushedArg = pushedRegs.Contains(reg);
                    var isImmediateRegArg = (i - leaIdx) == 1;

                    // Push-required renaming: only rewrite locals when we see the address actually passed on stack.
                    // Still emit a low-confidence hint for lea+call adjacency.
                    if (!isPushedArg && !isImmediateRegArg)
                        continue;

                    if (!isPushedArg)
                    {
                        if (hintedLocals.Add(loc))
                            aliasHints.Add($"VARHINT: {loc} maybe outparam (lea {reg}, [{loc}] immediately before call)");
                        continue;
                    }

                    if (inferredAliases.ContainsKey(loc))
                        continue;

                    var alias = MakeOutpAliasFromLocal(loc);
                    if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                        continue;

                    inferredAliases[loc] = alias;
                    aliasHints.Add($"VARALIAS: {loc} -> {alias} (outparam; inferred from push+call)");
                }
            }
        }

        private static void InferProtoHintsForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredOutAliases,
            out List<string> outAliasHints,
            out Dictionary<string, int> bitsByLocal,
            out int argCount,
            out string cc,
            out int? retImmBytes)
        {
            inferredOutAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            outAliasHints = new List<string>();
            bitsByLocal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            argCount = 0;
            cc = null;
            retImmBytes = null;

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Out-param alias tracking.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Track pushes in a small sliding window before calls.
            var pushRegCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var pushWindow = new Queue<string>();
            const int pushWindowSize = 12;

            // Args usage.
            var usedArgMax = -1;

            var max = Math.Min(instructions.Count, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
                var t = cooked.Trim();

                // Update arg usage (fast scan for arg_N).
                var pos = 0;
                while (pos < t.Length)
                {
                    pos = t.IndexOf("arg_", pos, StringComparison.OrdinalIgnoreCase);
                    if (pos < 0)
                        break;
                    var j = pos + 4;
                    var n = 0;
                    var any = false;
                    while (j < t.Length)
                    {
                        var ch = t[j];
                        if (ch < '0' || ch > '9')
                            break;
                        any = true;
                        n = (n * 10) + (ch - '0');
                        if (n > 4096)
                            break;
                        j++;
                    }
                    if (any)
                        usedArgMax = Math.Max(usedArgMax, n);
                    pos = j;
                }

                // Bit width hints (locals).
                var m = Regex.Match(t, @"^mov\s+\[(?<local>local_[0-9A-Fa-f]+)\]\s*,\s*(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\b", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    var bits = GetRegBitWidth(m.Groups["reg"].Value);
                    if (bits.HasValue)
                        MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                }
                else
                {
                    m = Regex.Match(t, @"^mov\s+(?<reg>e?[abcd]x|e?[sd]i|e?bp|e?sp|[abcd][lh])\s*,\s*\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                    if (m.Success)
                    {
                        var bits = GetRegBitWidth(m.Groups["reg"].Value);
                        if (bits.HasValue)
                            MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits.Value);
                    }
                    else
                    {
                        m = Regex.Match(t, @"\b(?<sz>byte|word|dword|qword|tword)\s+\[(?<local>local_[0-9A-Fa-f]+)\]", RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                            var sz = m.Groups["sz"].Value.ToLowerInvariant();
                            var bits = sz switch
                            {
                                "byte" => 8,
                                "word" => 16,
                                "dword" => 32,
                                "qword" => 64,
                                "tword" => 80,
                                _ => 0
                            };
                            if (bits > 0)
                                MergeBitWidthHint(bitsByLocal, m.Groups["local"].Value, bits);
                        }
                    }
                }

                // Track lea reg,[local] for outparam inference.
                if (TryParseLeaRegOfLocal(t, out var leaReg, out var localName))
                {
                    lastLeaLocalByReg[leaReg] = (localName, i);
                }

                // Track push reg window.
                if (TryParsePushReg(t, out var pushedReg))
                {
                    pushWindow.Enqueue(pushedReg);
                    pushRegCounts.TryGetValue(pushedReg, out var pc);
                    pushRegCounts[pushedReg] = pc + 1;

                    while (pushWindow.Count > pushWindowSize)
                    {
                        var old = pushWindow.Dequeue();
                        if (pushRegCounts.TryGetValue(old, out var oc))
                        {
                            oc--;
                            if (oc <= 0)
                                pushRegCounts.Remove(old);
                            else
                                pushRegCounts[old] = oc;
                        }
                    }
                }

                // Invalidate lea-tracked regs if this instruction writes a reg.
                var wm = WritesRegRegex.Match(t);
                if (wm.Success)
                {
                    var dst = wm.Groups["dst"].Value;
                    if (!string.IsNullOrWhiteSpace(dst))
                        lastLeaLocalByReg.Remove(dst);
                }

                // On call, decide whether any recent lea reg,[local] looks like an outparam.
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) && lastLeaLocalByReg.Count > 0)
                {
                    foreach (var kv in lastLeaLocalByReg.ToList())
                    {
                        var reg = kv.Key;
                        var (loc, leaIdx) = kv.Value;
                        if ((i - leaIdx) > 8)
                            continue;

                        var isPushedArg = pushRegCounts.ContainsKey(reg);
                        var isImmediateRegArg = (i - leaIdx) == 1;
                        if (!isPushedArg && !isImmediateRegArg)
                            continue;

                        if (!isPushedArg)
                        {
                            if (hintedLocals.Add(loc))
                                outAliasHints.Add($"VARHINT: {loc} maybe outparam (lea {reg}, [{loc}] immediately before call)");
                            continue;
                        }

                        if (inferredOutAliases.ContainsKey(loc))
                            continue;

                        var alias = MakeOutpAliasFromLocal(loc);
                        if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                            continue;

                        inferredOutAliases[loc] = alias;
                        outAliasHints.Add($"VARALIAS: {loc} -> {alias} (outparam; inferred from push+call)");
                    }
                }
            }

            // Determine calling convention / ret imm.
            for (var i = Math.Min(max, instructions.Count) - 1; i >= startIdx; i--)
            {
                var rt = InsText(instructions[i]).Trim();
                if (!rt.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    continue;

                var mret = Regex.Match(rt, @"^ret\s+(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                if (mret.Success && TryParseHexOrDecUInt32(mret.Groups["imm"].Value, out var imm))
                    retImmBytes = (int)imm;
                break;
            }

            if (retImmBytes.HasValue && retImmBytes.Value > 0)
            {
                cc = "stdcall";
                if (retImmBytes.Value % 4 == 0)
                    argCount = Math.Max(argCount, retImmBytes.Value / 4);
            }
            else
            {
                cc = "cdecl";
            }

            if (usedArgMax >= 0)
                argCount = Math.Max(argCount, usedArgMax + 1);
        }

        private static void InferOutParamLocalAliasesForFunction(
            string[] cookedByIndex,
            int startIdx,
            int endIdx,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (cookedByIndex == null || startIdx < 0 || endIdx <= startIdx)
                return;

            // Track most recent address-taken locals per register.
            var lastLeaLocalByReg = new Dictionary<string, (string local, int idx)>(StringComparer.OrdinalIgnoreCase);
            var hintedLocals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var max = Math.Min(cookedByIndex.Length, endIdx);
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i] ?? string.Empty;

                if (TryParseLeaRegOfLocal(cooked, out var leaReg, out var localName))
                {
                    lastLeaLocalByReg[leaReg] = (localName, i);
                    continue;
                }

                // Invalidate reg->local if the reg is overwritten.
                foreach (var k in lastLeaLocalByReg.Keys.ToList())
                {
                    if (InstructionWritesReg(cooked, k))
                        lastLeaLocalByReg.Remove(k);
                }

                var t = cooked.TrimStart();
                if (!t.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var pushedRegs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var back = Math.Max(startIdx, i - 10);
                for (var j = back; j < i; j++)
                {
                    var prev = cookedByIndex[j] ?? string.Empty;
                    if (TryParsePushReg(prev, out var pr))
                        pushedRegs.Add(pr);
                }

                foreach (var kv in lastLeaLocalByReg.ToList())
                {
                    var reg = kv.Key;
                    var (loc, leaIdx) = kv.Value;

                    if ((i - leaIdx) > 8)
                        continue;

                    var isPushedArg = pushedRegs.Contains(reg);
                    var isImmediateRegArg = (i - leaIdx) == 1;

                    if (!isPushedArg && !isImmediateRegArg)
                        continue;

                    if (!isPushedArg)
                    {
                        if (hintedLocals.Add(loc))
                            aliasHints.Add($"VARHINT: {loc} maybe outparam (lea {reg}, [{loc}] immediately before call)");
                        continue;
                    }

                    if (inferredAliases.ContainsKey(loc))
                        continue;

                    var alias = MakeOutpAliasFromLocal(loc);
                    if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                        continue;

                    inferredAliases[loc] = alias;
                    aliasHints.Add($"VARALIAS: {loc} -> {alias} (outparam; inferred from push+call)");
                }
            }
        }

        private static void InferArgsAndCallingConventionForFunction(
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out int argCount,
            out string cc,
            out int? retImmBytes)
        {
            argCount = 0;
            cc = null;
            retImmBytes = null;

            if (instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(instructions.Count, endIdx);
            var usedArgMax = -1;
            for (var i = startIdx; i < max; i++)
            {
                var cooked = RewriteStackFrameOperands(InsText(instructions[i]));
                foreach (Match m in Regex.Matches(cooked, @"\barg_(?<idx>[0-9]+)\b", RegexOptions.IgnoreCase))
                {
                    if (int.TryParse(m.Groups["idx"].Value, out var idx))
                        usedArgMax = Math.Max(usedArgMax, idx);
                }
            }

            // Find the last ret in the function range.
            for (var i = max - 1; i >= startIdx; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (!t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    continue;

                var m = Regex.Match(t, @"^ret\s+(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                if (m.Success && TryParseHexOrDecUInt32(m.Groups["imm"].Value, out var imm))
                    retImmBytes = (int)imm;
                break;
            }

            if (retImmBytes.HasValue && retImmBytes.Value > 0)
            {
                cc = "stdcall";
                if (retImmBytes.Value % 4 == 0)
                    argCount = Math.Max(argCount, retImmBytes.Value / 4);
            }
            else
            {
                cc = "cdecl";
            }

            if (usedArgMax >= 0)
                argCount = Math.Max(argCount, usedArgMax + 1);
        }

        private static void InferArgsAndCallingConventionForFunction(
            string[] cookedByIndex,
            List<Instruction> instructions,
            int startIdx,
            int endIdx,
            out int argCount,
            out string cc,
            out int? retImmBytes)
        {
            argCount = 0;
            cc = null;
            retImmBytes = null;

            if (cookedByIndex == null || instructions == null || startIdx < 0 || endIdx <= startIdx)
                return;

            var max = Math.Min(Math.Min(instructions.Count, endIdx), cookedByIndex.Length);
            var usedArgMax = -1;

            // Fast scan for arg_N tokens without regex.
            for (var i = startIdx; i < max; i++)
            {
                var cooked = cookedByIndex[i];
                if (string.IsNullOrEmpty(cooked))
                    continue;

                var idx = 0;
                while (idx < cooked.Length)
                {
                    idx = cooked.IndexOf("arg_", idx, StringComparison.OrdinalIgnoreCase);
                    if (idx < 0)
                        break;

                    var j = idx + 4;
                    var n = 0;
                    var any = false;
                    while (j < cooked.Length)
                    {
                        var ch = cooked[j];
                        if (ch < '0' || ch > '9')
                            break;
                        any = true;
                        n = (n * 10) + (ch - '0');
                        if (n > 4096)
                            break;
                        j++;
                    }

                    if (any)
                        usedArgMax = Math.Max(usedArgMax, n);

                    idx = j;
                }
            }

            // Find the last ret in the function range.
            for (var i = max - 1; i >= startIdx; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (!t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    continue;

                var m = Regex.Match(t, @"^ret\s+(?<imm>0x[0-9A-Fa-f]+|[0-9]+)\s*$", RegexOptions.IgnoreCase);
                if (m.Success && TryParseHexOrDecUInt32(m.Groups["imm"].Value, out var imm))
                    retImmBytes = (int)imm;
                break;
            }

            if (retImmBytes.HasValue && retImmBytes.Value > 0)
            {
                cc = "stdcall";
                if (retImmBytes.Value % 4 == 0)
                    argCount = Math.Max(argCount, retImmBytes.Value / 4);
            }
            else
            {
                cc = "cdecl";
            }

            if (usedArgMax >= 0)
                argCount = Math.Max(argCount, usedArgMax + 1);
        }

        private static string MakeOptAliasFromCase(byte caseVal)
        {
            if (caseVal >= (byte)'A' && caseVal <= (byte)'Z')
                return $"opt_{(char)caseVal}";
            if (caseVal >= (byte)'a' && caseVal <= (byte)'z')
                return $"opt_{(char)caseVal}";
            if (caseVal >= (byte)'0' && caseVal <= (byte)'9')
                return $"opt_{(char)caseVal}";
            return $"opt_0x{caseVal:X2}";
        }

        private static string MakeOutAliasFromCase(byte caseVal)
        {
            if (caseVal >= (byte)'A' && caseVal <= (byte)'Z')
                return $"out_{(char)caseVal}";
            if (caseVal >= (byte)'a' && caseVal <= (byte)'z')
                return $"out_{(char)caseVal}";
            if (caseVal >= (byte)'0' && caseVal <= (byte)'9')
                return $"out_{(char)caseVal}";
            return $"out_0x{caseVal:X2}";
        }

        private static void InferLocalAliasesFromSwitchCases(
            Dictionary<byte, string> roleByCase,
            out Dictionary<string, string> inferredAliases,
            out List<string> aliasHints)
        {
            inferredAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            aliasHints = new List<string>();

            if (roleByCase == null || roleByCase.Count == 0)
                return;

            var evidence = new Dictionary<string, LocalAliasEvidence>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in roleByCase)
            {
                var caseVal = kv.Key;
                var role = kv.Value;
                if (string.IsNullOrWhiteSpace(role))
                    continue;

                foreach (var part in role.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (TryParseRoleNoteSetLocal(part, out var local, out var v))
                    {
                        if (!evidence.TryGetValue(local, out var ev))
                            evidence[local] = ev = new LocalAliasEvidence();
                        ev.Cases.Add(caseVal);
                        ev.Values.Add(v);
                    }

                    if (TryParseRoleNoteAddrTaken(part, out var local2))
                    {
                        if (!evidence.TryGetValue(local2, out var ev2))
                            evidence[local2] = ev2 = new LocalAliasEvidence();
                        ev2.Cases.Add(caseVal);
                        ev2.AddressTaken = true;
                    }
                }
            }

            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in evidence.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var local = kv.Key;
                var ev = kv.Value;

                // Only rename when we have a fairly safe interpretation.
                // - boolean-ish options (only 0/1 writes, and at least one case sets to 1)
                // - address-taken locals (likely out parameters)
                var isBoolish = ev.Values.Count > 0 && ev.Values.All(v => v == 0 || v == 1) && ev.Values.Contains(1);

                byte? chosenCase = ev.Cases.OrderBy(c => c).FirstOrDefault();
                if (ev.Cases.Count > 0)
                    chosenCase = ev.Cases.OrderBy(c => c).First();

                string alias = null;
                if (isBoolish && chosenCase.HasValue)
                    alias = MakeOptAliasFromCase(chosenCase.Value);
                else if (!isBoolish && ev.AddressTaken && chosenCase.HasValue)
                    alias = MakeOutAliasFromCase(chosenCase.Value);

                if (string.IsNullOrWhiteSpace(alias) || !IsSafeAliasIdent(alias))
                    continue;

                // Ensure uniqueness.
                var baseAlias = alias;
                var suffix = 2;
                while (used.Contains(alias))
                {
                    alias = baseAlias + "_" + suffix;
                    suffix++;
                }
                used.Add(alias);

                inferredAliases[local] = alias;

                var caseText = string.Join(",", ev.Cases.OrderBy(c => c).Take(8).Select(c => FormatImm8AsChar(c) + $"(0x{c:X2})"));
                var valText = ev.Values.Count > 0 ? $" values={string.Join("/", ev.Values.OrderBy(v => v).Select(v => $"0x{v:X}"))}" : string.Empty;
                var kind = isBoolish ? "bool" : (ev.AddressTaken ? "out" : "local");
                aliasHints.Add($"VARALIAS: {local} -> {alias} ({kind}; cases {caseText}{valText})");
            }
        }

        private static void ScanStrings(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, out Dictionary<uint, string> symbols, out Dictionary<uint, string> preview)
        {
            symbols = new Dictionary<uint, string>();
            preview = new Dictionary<uint, string>();

            if (objects == null || objBytesByIndex == null)
                return;

            // Very lightweight string scan: runs of printable bytes terminated by 0.
            // To reduce noise, prefer scanning non-executable objects (data-ish).
            foreach (var obj in objects)
            {
                var isExecutable = (obj.Flags & 0x0004) != 0;
                if (isExecutable)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes) || bytes == null || bytes.Length == 0)
                    continue;

                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)bytes.Length);
                var i = 0;
                while (i < maxLen)
                {
                    // Find start of a printable run.
                    if (!IsLikelyStringChar(bytes[i]))
                    {
                        i++;
                        continue;
                    }

                    var start = i;
                    var sb = new StringBuilder();
                    while (i < maxLen && IsLikelyStringChar(bytes[i]) && sb.Length < 200)
                    {
                        sb.Append((char)bytes[i]);
                        i++;
                    }

                    // Require NUL terminator nearby to avoid random data.
                    var nul = (i < maxLen && bytes[i] == 0x00);
                    var s = sb.ToString();
                    if (nul && s.Length >= 4 && LooksLikeHumanString(s))
                    {
                        var linear = obj.BaseAddress + (uint)start;
                        if (!symbols.ContainsKey(linear))
                        {
                            symbols[linear] = $"s_{linear:X8}";
                            preview[linear] = EscapeForComment(s);
                        }
                    }

                    // Skip the terminator if present.
                    if (nul)
                        i++;
                }
            }
        }

        private static bool LooksLikeHumanString(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4)
                return false;

            var letters = 0;
            var digits = 0;
            var spaces = 0;
            var punctuation = 0;

            foreach (var ch in s)
            {
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
                    letters++;
                else if (ch >= '0' && ch <= '9')
                    digits++;
                else if (ch == ' ')
                    spaces++;
                else if (".,:;!?/\\-_()[]{}'\"".IndexOf(ch) >= 0)
                    punctuation++;
            }

            // Require at least some real “text signal”.
            if (letters < 2)
                return false;

            // Avoid things that are almost all hex-ish or symbols.
            if (letters + digits + spaces + punctuation == 0)
                return false;

            // Prefer either spaces or common punctuation or longer strings.
            return spaces > 0 || punctuation > 0 || s.Length >= 10;
        }

        private static bool IsLikelyStringChar(byte b)
        {
            // Accept basic printable ASCII plus a few common CP437 punctuation bytes.
            if (b >= 0x20 && b <= 0x7E)
                return true;
            // Tab
            if (b == 0x09)
                return true;
            return false;
        }

        private static string EscapeForComment(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;

            // Keep comments readable
            s = s.Replace("\\r", " ").Replace("\\n", " ").Replace("\t", " ");
            if (s.Length > 120)
                s = s.Substring(0, 120) + "...";
            return s;
        }

        private static string ApplyStringSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> stringSymbols, List<LEObject> objects = null)
        {
            if (stringSymbols == null || stringSymbols.Count == 0 || fixupsHere == null || fixupsHere.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!f.Value32.HasValue)
                    continue;

                var raw = f.Value32.Value;
                string sym = null;

                // Common case: raw already equals a linear string address.
                if (!stringSymbols.TryGetValue(raw, out sym))
                {
                    // Common DOS4GW pattern: raw is a small offset into a fixed resource region.
                    // If base+raw matches a known string symbol, rewrite the raw immediate to that symbol.
                    if (raw < 0x10000)
                    {
                        foreach (var baseAddr in new[] { 0x000C0000u, 0x000D0000u, 0x000E0000u, 0x000F0000u })
                        {
                            var linear = unchecked(baseAddr + raw);
                            if (stringSymbols.TryGetValue(linear, out sym))
                                break;
                        }
                    }

                    // Fallback: sometimes raw is object-relative and the fixup mapping tells us the true target.
                    if (objects != null && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                    {
                        var objIndex = f.TargetObject.Value;
                        if (objIndex >= 1 && objIndex <= objects.Count)
                        {
                            var linear = unchecked(objects[objIndex - 1].BaseAddress + f.TargetOffset.Value);
                            stringSymbols.TryGetValue(linear, out sym);
                        }
                    }
                }

                if (string.IsNullOrEmpty(sym))
                    continue;

                var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                if (!TryClassifyFixupKind(ins, delta, out var kind))
                    continue;

                // Strings typically appear as imm32 addresses (push/mov) but can be disp32 too.
                if (kind != "imm32" && kind != "imm32?" && kind != "disp32")
                    continue;

                var needleLower = $"0x{raw:x}";
                var needleUpper = $"0x{raw:X}";
                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }

        private static void BuildBasicBlocks(List<Instruction> instructions, uint startLinear, uint endLinear, HashSet<uint> functionStarts, HashSet<uint> labelTargets,
            out HashSet<uint> blockStarts, out Dictionary<uint, List<uint>> blockPreds)
        {
            blockStarts = new HashSet<uint>();
            blockPreds = new Dictionary<uint, List<uint>>();

            if (instructions == null || instructions.Count == 0)
                return;

            foreach (var f in functionStarts)
                blockStarts.Add(f);
            foreach (var t in labelTargets)
                blockStarts.Add(t);

            // Add fallthrough starts after conditional branches.
            for (var i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                var addr = (uint)ins.Offset;
                var nextAddr = addr + (uint)ins.Length;

                if (TryGetRelativeBranchTarget(ins, out var target, out var isCall))
                {
                    if (!isCall)
                    {
                        // Branch target is already a block start via labelTargets.
                        if (nextAddr >= startLinear && nextAddr < endLinear && IsConditionalBranch(ins))
                            blockStarts.Add(nextAddr);

                        // Precompute preds
                        AddPred(blockPreds, target, addr);
                        if (IsConditionalBranch(ins))
                            AddPred(blockPreds, nextAddr, addr);
                    }
                }
            }
        }

        private static void AddPred(Dictionary<uint, List<uint>> preds, uint dst, uint src)
        {
            if (!preds.TryGetValue(dst, out var list))
                preds[dst] = list = new List<uint>();
            list.Add(src);
        }

        private static bool IsConditionalBranch(Instruction ins)
        {
            if (ins == null)
                return false;
            // Cheap heuristic based on mnemonic text
            var s = InsText(ins);
            return s.StartsWith("j", StringComparison.OrdinalIgnoreCase) &&
                   !s.StartsWith("jmp", StringComparison.OrdinalIgnoreCase);
        }

        private static Dictionary<uint, FunctionSummary> SummarizeFunctions(
            List<Instruction> instructions,
            HashSet<uint> functionStarts,
            HashSet<uint> blockStarts,
            Dictionary<uint, List<LEFixup>> fixupsByInsAddr,
            Dictionary<uint, string> globalSymbols,
            Dictionary<uint, string> stringSymbols)
        {
            var summaries = new Dictionary<uint, FunctionSummary>();
            if (instructions == null || instructions.Count == 0 || functionStarts == null || functionStarts.Count == 0)
                return summaries;

            // Sort function starts by address and use next start as boundary.
            var starts = functionStarts.OrderBy(x => x).ToList();

            // Precompute instruction start addresses for binary search.
            var insStarts = new uint[instructions.Count];
            for (var i = 0; i < instructions.Count; i++)
                insStarts[i] = (uint)instructions[i].Offset;

            // Optional: speed up block counts.
            uint[] sortedBlocks = null;
            if (blockStarts != null && blockStarts.Count > 0)
                sortedBlocks = blockStarts.OrderBy(x => x).ToArray();

            static int LowerBound(uint[] arr, uint value)
            {
                if (arr == null || arr.Length == 0)
                    return 0;
                var idx = Array.BinarySearch(arr, value);
                return idx < 0 ? ~idx : idx;
            }

            for (var si = 0; si < starts.Count; si++)
            {
                var start = starts[si];
                var end = (si + 1 < starts.Count) ? starts[si + 1] : uint.MaxValue;

                var summary = new FunctionSummary { Start = start };
                summaries[start] = summary;

                // Walk the instruction slice [start, end).
                var startIdx = LowerBound(insStarts, start);
                var endIdx = end == uint.MaxValue ? instructions.Count : LowerBound(insStarts, end);
                if (startIdx < 0)
                    startIdx = 0;
                if (endIdx > instructions.Count)
                    endIdx = instructions.Count;
                if (startIdx > endIdx)
                    (startIdx, endIdx) = (endIdx, startIdx);

                for (var ii = startIdx; ii < endIdx; ii++)
                {
                    var ins = instructions[ii];
                    var addr = (uint)ins.Offset;
                    if (addr < start)
                        continue;
                    if (addr >= end)
                        break;

                    summary.InstructionCount++;

                    if (TryGetRelativeBranchTarget(ins, out var target, out var isCall) && isCall)
                        summary.Calls.Add(target);

                    if (fixupsByInsAddr != null && fixupsByInsAddr.TryGetValue(addr, out var fx) && fx != null && fx.Count > 0)
                    {
                        foreach (var f in fx)
                        {
                            if (!f.Value32.HasValue)
                                continue;

                            if (globalSymbols != null && globalSymbols.TryGetValue(f.Value32.Value, out var g))
                                summary.Globals.Add(g);
                            if (stringSymbols != null && stringSymbols.TryGetValue(f.Value32.Value, out var s))
                                summary.Strings.Add(s);
                        }
                    }
                }

                if (sortedBlocks != null && sortedBlocks.Length > 0)
                {
                    var b0 = LowerBound(sortedBlocks, start);
                    var b1 = end == uint.MaxValue ? sortedBlocks.Length : LowerBound(sortedBlocks, end);
                    summary.BlockCount = Math.Max(0, b1 - b0);
                }
            }

            return summaries;
        }

        private static string TryGetCallArgHint(List<Instruction> instructions, Dictionary<uint, int> insIndexByAddr, Instruction ins, List<LEFixup> fixupsHere,
            Dictionary<uint, string> globalSymbols, Dictionary<uint, string> stringSymbols)
        {
            if (ins == null || instructions == null || insIndexByAddr == null)
                return string.Empty;

            // Only for call instructions.
            var text = InsText(ins);
            if (!text.StartsWith("call ", StringComparison.OrdinalIgnoreCase))
                return string.Empty;

            if (!insIndexByAddr.TryGetValue((uint)ins.Offset, out var idx))
                return string.Empty;

            // Count push instructions immediately preceding within a short window.
            var pushes = 0;
            for (var i = idx - 1; i >= 0 && i >= idx - 8; i--)
            {
                var t = InsText(instructions[i]);
                if (t.StartsWith("push ", StringComparison.OrdinalIgnoreCase))
                {
                    pushes++;
                    continue;
                }
                // Stop if stack pointer adjusted or another call/ret/branch intervenes.
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) || t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase))
                    break;
                if (t.StartsWith("add esp", StringComparison.OrdinalIgnoreCase) || t.StartsWith("sub esp", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            // Heuristic for return usage: next instruction mentions eax.
            var retUsed = false;
            if (idx + 1 < instructions.Count)
            {
                var next = InsText(instructions[idx + 1]);
                if (next.IndexOf("eax", StringComparison.OrdinalIgnoreCase) >= 0)
                    retUsed = true;
            }

            // Best-effort register-arg note (common in Watcom/DOS4GW style code)
            // This doesn't assume a calling convention; it simply records obvious setup like "movzx edx, word [0x....]" right before call.
            var regArgNotes = new List<string>();
            for (var i = idx - 1; i >= 0 && i >= idx - 6; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (TryParseSimpleRegSetup(t, "edx", out var rhsEdx))
                {
                    regArgNotes.Add($"edx={rhsEdx}");
                    break;
                }
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    break;
            }
            for (var i = idx - 1; i >= 0 && i >= idx - 6; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (TryParseSimpleRegSetup(t, "eax", out var rhsEax))
                {
                    regArgNotes.Add($"eax={rhsEax}");
                    break;
                }
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    break;
            }
            for (var i = idx - 1; i >= 0 && i >= idx - 6; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (TryParseSimpleRegSetup(t, "ecx", out var rhsEcx))
                {
                    regArgNotes.Add($"ecx={rhsEcx}");
                    break;
                }
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                    break;
            }

            var regText = regArgNotes.Count > 0 ? $" reg~{string.Join(",", regArgNotes)}" : string.Empty;
            return $"args~{pushes} ret={(retUsed ? "eax" : "(unused?)")}{regText}";
        }

        private static bool TryParseSimpleRegSetup(string insText, string reg, out string rhs)
        {
            rhs = null;
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // mov reg, rhs
            var m1 = Regex.Match(insText, $@"^\s*mov\s+{Regex.Escape(reg)}\s*,\s*(?<rhs>.+?)\s*$", RegexOptions.IgnoreCase);
            if (m1.Success)
            {
                rhs = m1.Groups["rhs"].Value.Trim();
                rhs = rhs.Length > 48 ? rhs.Substring(0, 48) + "..." : rhs;
                return true;
            }

            // movzx reg, word [mem]
            var m2 = Regex.Match(insText, $@"^\s*movzx\s+{Regex.Escape(reg)}\s*,\s*(?<rhs>.+?)\s*$", RegexOptions.IgnoreCase);
            if (m2.Success)
            {
                rhs = m2.Groups["rhs"].Value.Trim();
                rhs = rhs.Length > 48 ? rhs.Substring(0, 48) + "..." : rhs;
                return true;
            }

            return false;
        }

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

        private static string TryAnnotateBasicBlockSummary(List<Instruction> instructions, int startIdx)
        {
            if (instructions == null || startIdx < 0 || startIdx >= instructions.Count)
                return string.Empty;

            var hints = new List<string>();

            var restoreHint = TryAnnotateRestoreCachedGlobalsToEsi(instructions, startIdx);
            if (!string.IsNullOrEmpty(restoreHint))
                hints.Add(restoreHint);

            // Detect repeated pattern:
            //   mov r32, [esi+disp]
            //   mov [abs32], r32
            // repeated several times to "cache" fields from a struct pointed by ESI.
            var pairs = new List<(int disp, uint abs)>();
            var scanLimit = Math.Min(instructions.Count, startIdx + 20);

            for (var i = startIdx; i + 1 < scanLimit; i++)
            {
                var a = InsText(instructions[i]).Trim();
                var b = InsText(instructions[i + 1]).Trim();

                if (!TryParseMovRegFromEsiDisp(a, out var reg, out var disp))
                    continue;
                if (!TryParseMovAbsFromReg(b, reg, out var abs))
                    continue;

                pairs.Add((disp, abs));
                i++; // consume the store
            }

            if (pairs.Count >= 3)
            {
                // Prefer an explicit mapping list (more useful than a min/max range since globals may not be monotonic).
                var mappingParts = pairs
                    .Take(6)
                    .Select(p => $"+0x{p.disp:X}->0x{p.abs:X}")
                    .ToList();

                var mappingText = string.Join(", ", mappingParts);
                if (pairs.Count > 6)
                    mappingText += ", ...";

                hints.Add($"BBHINT: cache [esi+disp] to globals: {mappingText} ({pairs.Count} stores)");
            }

            var crit = TryAnnotateCriticalSectionIo(instructions, startIdx);
            if (!string.IsNullOrEmpty(crit))
                hints.Add(crit);

            return hints.Count > 0 ? string.Join(" ; ", hints) : string.Empty;
        }

        private static bool TryParseCmpAbsImm(string insText, out uint abs, out uint imm)
        {
            abs = 0;
            imm = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var m = Regex.Match(insText.Trim(), @"^cmp\s+(?:byte|word|dword)?\s*\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var absTok = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
            var immTok = m.Groups["imm"].Value.Trim().TrimEnd('h', 'H');
            if (!TryParseHexOrDecUInt32(absTok, out abs))
                return false;
            if (!TryParseHexOrDecUInt32(immTok, out imm))
                return false;
            return true;
        }

        private static bool TryParseMovAbsImm(string insText, out uint abs, out uint imm)
        {
            abs = 0;
            imm = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            var m = Regex.Match(insText.Trim(), @"^mov\s+(?:byte|word|dword)?\s*\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var absTok = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
            var immTok = m.Groups["imm"].Value.Trim().TrimEnd('h', 'H');
            if (!TryParseHexOrDecUInt32(absTok, out abs))
                return false;
            if (!TryParseHexOrDecUInt32(immTok, out imm))
                return false;
            return true;
        }

        private static string TryAnnotateInitOnceSentinel(List<Instruction> instructions, int idx, Dictionary<uint, string> ptrSymbols)
        {
            if (instructions == null || idx < 0 || idx >= instructions.Count)
                return string.Empty;

            var t = InsText(instructions[idx]).Trim();
            if (!TryParseCmpAbsImm(t, out var abs, out var immCmp))
                return string.Empty;

            var scanLimit = Math.Min(instructions.Count, idx + 12);
            for (var j = idx + 1; j < scanLimit; j++)
            {
                var u = InsText(instructions[j]).Trim();
                if (!TryParseMovAbsImm(u, out var abs2, out var immMov))
                    continue;
                if (abs2 != abs)
                    continue;

                var name = ptrSymbols != null && ptrSymbols.TryGetValue(abs, out var sym) ? $"[{sym}]" : $"[0x{abs:X}]";

                if (immMov == immCmp)
                    return $"INIT: sentinel {name} == 0x{immCmp:X} (init-once / cache-valid?)";

                if ((immCmp == 0 || immCmp == 1) && (immMov == 0 || immMov == 1))
                    return $"INIT: sentinel {name} {immCmp}-> {immMov} (init-once?)";

                return $"INIT: sentinel {name} (cmp 0x{immCmp:X} then set 0x{immMov:X})";
            }

            return string.Empty;
        }

        private static bool TryParseAbsBitTest(string insText, out uint abs, out uint mask)
        {
            abs = 0;
            mask = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // Examples:
            //   test dword [0xbab6c], 0x4
            //   test byte [0x1234], 0x40
            var m = Regex.Match(insText.Trim(), @"^test\s+(?:byte|word|dword)\s+\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var absTok = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
            var immTok = m.Groups["imm"].Value.Trim().TrimEnd('h', 'H');

            if (!TryParseHexOrDecUInt32(absTok, out abs))
                return false;
            if (!TryParseHexOrDecUInt32(immTok, out mask))
                return false;
            return true;
        }

        private static void CollectFlagBitTestsForFunction(List<Instruction> instructions, int startIdx, int endIdx, out Dictionary<uint, FlagBitStats> statsByAbs)
        {
            statsByAbs = new Dictionary<uint, FlagBitStats>();
            if (instructions == null || startIdx < 0 || endIdx > instructions.Count || startIdx >= endIdx)
                return;

            for (var i = startIdx; i < endIdx; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (!TryParseAbsBitTest(t, out var abs, out var mask))
                    continue;

                // Only summarize single-bit tests; multi-bit masks are noisy.
                if (mask == 0 || (mask & (mask - 1)) != 0)
                    continue;

                var bit = 0;
                var x = mask;
                while (x > 1) { x >>= 1; bit++; }

                if (!statsByAbs.TryGetValue(abs, out var st))
                    statsByAbs[abs] = st = new FlagBitStats();

                st.Total++;
                if (!st.BitCounts.TryGetValue(bit, out var c)) c = 0;
                st.BitCounts[bit] = c + 1;
            }
        }

        private static string FormatFlagBitSummary(Dictionary<uint, FlagBitStats> statsByAbs, Dictionary<uint, string> flagSymbols)
        {
            if (statsByAbs == null || statsByAbs.Count == 0)
                return string.Empty;

            var parts = new List<string>();

            foreach (var kvp in statsByAbs.OrderByDescending(k => k.Value.Total).ThenBy(k => k.Key).Take(3))
            {
                var abs = kvp.Key;
                var st = kvp.Value;

                var bits = st.BitCounts
                    .OrderByDescending(b => b.Value)
                    .ThenBy(b => b.Key)
                    .Take(8)
                    .Select(b => $"{b.Key}(x{b.Value})")
                    .ToList();

                if (flagSymbols != null && flagSymbols.TryGetValue(abs, out var sym))
                    parts.Add($"[{sym}] bits {string.Join(",", bits)}");
                else
                    parts.Add($"[0x{abs:X}] bits {string.Join(",", bits)}");
            }

            return string.Join(" ; ", parts);
        }

        private static string TryAnnotateRestoreCachedGlobalsToEsi(List<Instruction> instructions, int startIdx)
        {
            // Detect repeated pattern:
            //   mov reg, [abs]
            //   mov [esi+disp], reg
            // which commonly restores a cached struct state.
            var pairs = new List<(uint abs, int disp)>();
            var scanLimit = Math.Min(instructions.Count, startIdx + 24);

            for (var i = startIdx; i + 1 < scanLimit; i++)
            {
                var a = InsText(instructions[i]).Trim();
                var b = InsText(instructions[i + 1]).Trim();

                if (!TryParseMovRegFromAbs(a, out var reg, out var abs))
                    continue;
                if (!TryParseMovEsiDispFromReg(b, reg, out var disp))
                    continue;

                pairs.Add((abs, disp));
                i++; // consume store
            }

            if (pairs.Count < 3)
                return string.Empty;

            var mappingParts = pairs
                .Take(6)
                .Select(p => $"0x{p.abs:X}->+0x{p.disp:X}")
                .ToList();

            var mappingText = string.Join(", ", mappingParts);
            if (pairs.Count > 6)
                mappingText += ", ...";

            return $"BBHINT: restore globals to [esi+disp]: {mappingText} ({pairs.Count} stores)";
        }

        private static bool TryParseMovRegFromEsiDisp(string insText, out string reg, out int disp)
        {
            reg = null;
            disp = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // e.g. "mov eax, [esi+0x30]" or "mov edx, [esi+0x30]"
            var m = Regex.Match(insText, @"^\s*mov\s+(?<reg>e[a-d]x|e[sdi]i|e[bp]p|[a-d]x|[sb]p|[sd]i|[a-d][lh])\s*,\s*\[esi\+(?<disp>0x[0-9A-Fa-f]+|[0-9]+)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            var d = m.Groups["disp"].Value;

            if (d.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(d.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out disp))
                    return false;
            }
            else
            {
                if (!int.TryParse(d, out disp))
                    return false;
            }

            return true;
        }

        private static bool TryParseMovRegFromAbs(string insText, out string reg, out uint abs)
        {
            reg = null;
            abs = 0;
            if (string.IsNullOrWhiteSpace(insText))
                return false;

            // e.g. "mov eax, [0xc25c0]"
            var m = Regex.Match(insText, @"^\s*mov\s+(?<reg>e[a-d]x|e[sdi]i|e[bp]p|[a-d]x|[sb]p|[sd]i|[a-d][lh])\s*,\s*\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            reg = m.Groups["reg"].Value.ToLowerInvariant();
            var token = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');

            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return uint.TryParse(token.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out abs);

            var isHex = token.Any(c => (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
            return isHex
                ? uint.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out abs)
                : uint.TryParse(token, out abs);
        }

        private static bool TryParseMovEsiDispFromReg(string insText, string reg, out int disp)
        {
            disp = 0;
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // e.g. "mov [esi+0x30], eax" or "mov [esi+0x29], dl"
            var m = Regex.Match(insText, $@"^\s*mov\s+\[esi\+(?<disp>0x[0-9A-Fa-f]+|[0-9]+)\]\s*,\s*{Regex.Escape(reg)}\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var d = m.Groups["disp"].Value;
            if (d.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(d.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out disp);
            return int.TryParse(d, out disp);
        }

        private static string TryAnnotateGenericInstruction(string rawInsText, Dictionary<uint, string> flagSymbols)
        {
            if (string.IsNullOrWhiteSpace(rawInsText))
                return string.Empty;

            var t = rawInsText.Trim();
            if (t.Equals("cli", StringComparison.OrdinalIgnoreCase))
                return "IRQ: disable interrupts";
            if (t.Equals("sti", StringComparison.OrdinalIgnoreCase))
                return "IRQ: enable interrupts";
            if (t.StartsWith("retf", StringComparison.OrdinalIgnoreCase))
                return "RET: far return";
            if (t.Equals("clc", StringComparison.OrdinalIgnoreCase))
                return "FLAGS: CF=0 (success?)";
            if (t.Equals("stc", StringComparison.OrdinalIgnoreCase))
                return "FLAGS: CF=1 (failure?)";

            if (t.Equals("pop esp", StringComparison.OrdinalIgnoreCase))
                return "NOTE: pop esp (stack pivot / unusual; may indicate misdecode)";

            // Flag-bit tests like: test dword [0xBAB6C], 0x4
            var m = Regex.Match(t, @"^test\s+(?:byte|word|dword)\s+\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*(?<imm>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?|\d+)\s*$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var absTok = m.Groups["abs"].Value.Trim().TrimEnd('h', 'H');
                var immTok = m.Groups["imm"].Value.Trim().TrimEnd('h', 'H');

                if (TryParseHexOrDecUInt32(immTok, out var imm) && imm != 0 && (imm & (imm - 1)) == 0)
                {
                    var bit = 0;
                    var x = imm;
                    while (x > 1) { x >>= 1; bit++; }

                    var label = NormalizeAbsToken(absTok);
                    if (TryParseHexOrDecUInt32(absTok, out var abs) && flagSymbols != null && flagSymbols.TryGetValue(abs, out var sym))
                        label = sym;

                    return $"FLAGS: test bit {bit} (mask 0x{imm:X}) of [{label}]";
                }
            }

            if (t.StartsWith("lgs ", StringComparison.OrdinalIgnoreCase))
                return "PTR: load far pointer + selector (protected mode)";

            return string.Empty;
        }

        private static bool TryParseHexOrDecUInt32(string token, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(token))
                return false;

            token = token.Trim();
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return uint.TryParse(token.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out value);

            var isHex = token.Any(c => (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
            return isHex
                ? uint.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out value)
                : uint.TryParse(token, out value);
        }

        private static string NormalizeAbsToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return token;
            token = token.Trim();
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return "0x" + token.Substring(2).ToUpperInvariant();
            // If it looks hex, normalize into 0x....
            var isHex = token.Any(c => (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
            return isHex ? "0x" + token.ToUpperInvariant() : token;
        }

        private static bool TryParseMovAbsFromReg(string insText, string reg, out uint abs)
        {
            abs = 0;
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(reg))
                return false;

            // e.g. "mov [0xc25c0], eax"
            var m = Regex.Match(insText, $@"^\s*mov\s+\[(?<abs>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h?)\]\s*,\s*{Regex.Escape(reg)}\s*$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            var token = m.Groups["abs"].Value.Trim();
            token = token.TrimEnd('h', 'H');
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (!uint.TryParse(token.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out abs))
                    return false;
                return true;
            }

            // If it contains A-F treat as hex.
            var isHex = token.Any(c => (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
            if (isHex)
            {
                if (!uint.TryParse(token, System.Globalization.NumberStyles.HexNumber, null, out abs))
                    return false;
                return true;
            }
            if (!uint.TryParse(token, out abs))
                return false;
            return true;
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
            // Minimal, commonly encountered DPMI services (not exhaustive)
            switch (ax)
            {
                case 0x0000: return "Allocate LDT descriptors";
                case 0x0001: return "Free LDT descriptor";
                case 0x0007: return "Set segment base";
                case 0x0008: return "Set segment limit";
                case 0x0100: return "Allocate DOS memory block";
                case 0x0101: return "Free DOS memory block";
                case 0x0300: return "Simulate real-mode interrupt";
                case 0x0400: return "Get DPMI version";
                default:
                    return string.Empty;
            }
        }

        private static string TryAnnotateJumpTable(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int insLoopIndex,
            Instruction ins,
            List<LEFixup> fixupsHere,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Dictionary<uint, string> stringSymbols,
            Dictionary<uint, string> globalSymbols)
        {
            if (ins?.Bytes == null || ins.Bytes.Length < 7)
                return string.Empty;

            // Look for (optionally with prefixes, e.g. cs: 0x2E):
            //   FF 24 85 xx xx xx xx  (jmp dword [eax*4 + disp32])
            // ModRM=0x24 => rm=100 (SIB), reg=4 (JMP), mod=00
            if (!TryParseIndirectJmpTable(ins.Bytes, out var disp, out var indexReg, out var scale))
                return string.Empty;

            var reg = string.IsNullOrWhiteSpace(indexReg) ? "?" : indexReg;

            var want = 8;
            if (TryInferJumpTableSwitchBound(instructions, insLoopIndex, indexReg, out var inferredCases, out var _))
                want = Math.Min(64, Math.Max(1, inferredCases));

            if (TryResolveJumpTableTargets(instructions, insIndexByAddr, insLoopIndex, ins, objects, objBytesByIndex, want, out var tableBase, out var targets, out var mode))
            {
                var symResolved = globalSymbols != null && globalSymbols.TryGetValue(tableBase, out var gResolved) ? gResolved : $"0x{tableBase:X8}";
                var shownResolved = string.Join(", ", targets.Take(8).Select(x => $"0x{x:X8}"));
                var modeSuffix = string.IsNullOrWhiteSpace(mode) ? string.Empty : $" {mode}";
                return $"JUMPTABLE: idx={reg} stride={scale} base={symResolved}{modeSuffix} entries~{targets.Count} [{shownResolved}{(targets.Count > 8 ? ", ..." : string.Empty)}]";
            }

            // The disp32 in the encoding may be:
            //  - a flat linear address, OR
            //  - an object-relative offset (segment base added at runtime).
            // We try both and pick the one that yields plausible table entries.
            var base1 = disp;
            var base2 = 0u;
            if (TryMapLinearToObject(objects, (uint)ins.Offset, out var curObj, out var _))
            {
                var curBase = objects != null && curObj > 0 && curObj - 1 < objects.Count ? objects[curObj - 1].BaseAddress : 0u;
                base2 = curBase + disp;
            }

            var max = 16;
            var entrySize = HasOperandSizeOverridePrefix(ins.Bytes) ? 2 : 4;
            TryReadJumpTableEntries(objects, objBytesByIndex, base1, max, stride: scale, entrySize: entrySize, out var entries1, out var raw1, out var adjByBase1);
            TryReadJumpTableEntries(objects, objBytesByIndex, base2, max, stride: scale, entrySize: entrySize, out var entries2, out var raw2, out var adjByBase2);

            var useBase = base1;
            var entries = entries1;
            var raw = raw1;
            var adjustedByBase = adjByBase1;
            if ((entries2?.Count ?? 0) > (entries1?.Count ?? 0))
            {
                useBase = base2;
                entries = entries2;
                raw = raw2;
                adjustedByBase = adjByBase2;
            }

            if (useBase == 0 || entries == null || raw == null)
                return string.Empty;

            var sym = globalSymbols != null && globalSymbols.TryGetValue(useBase, out var g) ? g : $"0x{useBase:X8}";
            if (entries.Count == 0)
            {
                var rawShown = raw.Count == 0 ? string.Empty : string.Join(", ", raw.Take(6).Select(x => $"0x{x:X8}"));
                var rawSuffix = string.IsNullOrEmpty(rawShown) ? string.Empty : $" raw=[{rawShown}{(raw.Count > 6 ? ", ..." : string.Empty)}]";
                return $"JUMPTABLE: idx={reg} base={sym} entries=0{rawSuffix}";
            }

            var shown = string.Join(", ", entries.Select(x => $"0x{x:X8}").Take(8));
            var adjSuffix = adjustedByBase ? " adj=+objbase" : string.Empty;
            return $"JUMPTABLE: idx={reg} base={sym}{adjSuffix} entries~{entries.Count} [{shown}{(entries.Count > 8 ? ", ..." : string.Empty)}]";
        }

        private static bool TryResolveJumpTableTargets(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int jmpIdx,
            Instruction jmpIns,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            int wantEntries,
            out uint tableBaseLinear,
            out List<uint> targets,
            out string mode)
        {
            tableBaseLinear = 0;
            targets = null;
            mode = string.Empty;
            if (jmpIns?.Bytes == null || insIndexByAddr == null || objects == null || objBytesByIndex == null)
                return false;

            if (!TryParseIndirectJmpTable(jmpIns.Bytes, out var dispU32, out var baseReg, out var indexReg, out var scale, out var dispSigned, out var _))
                return false;

            var entrySize = HasOperandSizeOverridePrefix(jmpIns.Bytes) ? 2 : 4;
            var stride = scale;
            if (stride != 1 && stride != 2 && stride != 4 && stride != 8)
                return false;

            // Determine current object and bytes.
            if (!TryMapLinearToObject(objects, (uint)jmpIns.Offset, out var curObj, out var curOff))
                return false;
            if (!objBytesByIndex.TryGetValue(curObj, out var curBytes) || curBytes == null)
                return false;

            var curBase = objects[curObj - 1].BaseAddress;

            var want = Math.Min(64, Math.Max(1, wantEntries));
            // For scoring, we only need a small prefix.
            var wantScan = Math.Min(8, want);
            var bestScore = -1;
            uint bestBase = 0;
            var bestTargets = (List<uint>)null;
            var bestMode = string.Empty;

            int ScoreTableAtLinear(uint baseLinear, string m, out List<uint> list)
            {
                list = null;
                if (baseLinear == 0)
                    return -1;
                if (!TryMapLinearToObject(objects, baseLinear, out var tob, out var toff))
                    return -1;
                if (!objBytesByIndex.TryGetValue(tob, out var bytes) || bytes == null)
                    return -1;
                var objBase = objects[tob - 1].BaseAddress;
                var off0 = (int)toff;
                if (off0 < 0 || off0 + entrySize > bytes.Length)
                    return -1;

                var tmp = new List<uint>();
                var hits = 0;
                var distinct = new HashSet<uint>();
                var badZero = 0;

                for (var i = 0; i < wantScan; i++)
                {
                    var off = off0 + i * stride;
                    if (off + entrySize > bytes.Length)
                        break;

                    uint v;
                    if (entrySize == 2)
                        v = (uint)(bytes[off] | (bytes[off + 1] << 8));
                    else
                        v = (uint)(bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24));

                    if (v == 0)
                        badZero++;

                    uint t = m switch
                    {
                        "abs" => v,
                        "csbase" => objBase + v,
                        "rel" => unchecked((uint)((int)jmpIns.Offset + (int)v)),
                        _ => v,
                    };

                    tmp.Add(t);
                    distinct.Add(t);
                    if (insIndexByAddr.ContainsKey(t))
                        hits++;
                }

                if (tmp.Count < Math.Min(3, wantScan))
                    return -1;

                var score = hits * 10 + distinct.Count - badZero * 2;
                if (distinct.Count <= 1)
                    score -= 10;

                list = tmp;
                return score;
            }

            int ScoreTableAtOffset(int off0, string m, out List<uint> list)
            {
                list = null;
                if (off0 < 0 || off0 + entrySize > curBytes.Length)
                    return -1;

                var tmp = new List<uint>();
                var hits = 0;
                var distinct = new HashSet<uint>();
                var badZero = 0;

                for (var i = 0; i < wantScan; i++)
                {
                    var off = off0 + i * stride;
                    if (off + entrySize > curBytes.Length)
                        break;
                    uint v;
                    if (entrySize == 2)
                    {
                        v = (uint)(curBytes[off] | (curBytes[off + 1] << 8));
                    }
                    else
                    {
                        v = (uint)(curBytes[off] | (curBytes[off + 1] << 8) | (curBytes[off + 2] << 16) | (curBytes[off + 3] << 24));
                    }
                    if (v == 0)
                        badZero++;

                    uint t = m switch
                    {
                        "abs" => v,
                        "csbase" => curBase + v,
                        "rel" => unchecked((uint)((int)jmpIns.Offset + (int)v)),
                        _ => v,
                    };

                    tmp.Add(t);
                    distinct.Add(t);
                    if (insIndexByAddr.ContainsKey(t))
                        hits++;
                }

                if (tmp.Count < Math.Min(3, wantScan))
                    return -1;

                // Prefer many decoded targets + distinctness; penalize all-zero tables.
                var score = hits * 10 + distinct.Count - badZero * 2;
                if (distinct.Count <= 1)
                    score -= 10;

                list = tmp;
                return score;
            }

            void ConsiderTable(uint candBase)
            {
                if (candBase == 0)
                    return;
                foreach (var m in new[] { "abs", "csbase", "rel" })
                {
                    var score = ScoreTableAtLinear(candBase, m, out var list);
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestBase = candBase;
                        bestTargets = list;
                        bestMode = m;
                    }
                }
            }

            // 1) Try the two most likely base interpretations.
            ConsiderTable(curBase + dispU32);
            ConsiderTable(dispU32);

            // 1b) If the SIB base is a register, try to resolve it to a table pointer.
            if (!string.IsNullOrWhiteSpace(baseReg) && TryResolveRegisterAsTablePointer(instructions, jmpIdx, baseReg, objects, objBytesByIndex, out var basePtr, out var _src) && basePtr != 0)
            {
                var cand = unchecked(basePtr + (uint)dispSigned);
                ConsiderTable(cand);
            }

            // 2) Scan near the dispatch (common compiler placement).
            {
                var around = (int)curOff;
                var start = Math.Max(0, around - 0x400);
                var end = Math.Min(curBytes.Length - 4, around + 0x8000);
                for (var off = start; off <= end; off += 4)
                {
                    foreach (var m in new[] { "abs", "csbase" })
                    {
                        var score = ScoreTableAtOffset(off, m, out var list);
                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestBase = curBase + (uint)off;
                            bestTargets = list;
                            bestMode = m;
                        }
                    }
                }
            }

            // 3) If still nothing, scan around the disp-derived offsets within the object.
            if (bestScore < 20)
            {
                foreach (var cand in new[] { curBase + dispU32, dispU32 })
                {
                    if (!TryMapLinearToObject(objects, cand, out var tob, out var toff) || tob != curObj)
                        continue;
                    var center = (int)toff;
                    var start = Math.Max(0, center - 0x8000);
                    var end = Math.Min(curBytes.Length - 4, center + 0x8000);
                    for (var off = start; off <= end; off += 4)
                    {
                        foreach (var m in new[] { "abs", "csbase" })
                        {
                            var score = ScoreTableAtOffset(off, m, out var list);
                            if (score > bestScore)
                            {
                                bestScore = score;
                                bestBase = curBase + (uint)off;
                                bestTargets = list;
                                bestMode = m;
                            }
                        }
                    }
                }
            }

            // 4) Last resort: full object scan (still cheap for small wantScan).
            if (bestScore < 20)
            {
                for (var off = 0; off + entrySize <= curBytes.Length; off += 4)
                {
                    foreach (var m in new[] { "abs", "csbase" })
                    {
                        var score = ScoreTableAtOffset(off, m, out var list);
                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestBase = curBase + (uint)off;
                            bestTargets = list;
                            bestMode = m;
                            if (bestScore >= wantScan * 10 + wantScan)
                                break;
                        }
                    }
                }
            }

            // For small switches (<=8), accept 2 hits if they're distinct.
            var minScore = wantScan <= 8 ? 12 : 25;
            if (bestScore < minScore || bestTargets == null)
                return false;

            tableBaseLinear = bestBase;
            // Trim to inferred case count if we have it.
            if (TryInferJumpTableSwitchBound(instructions, jmpIdx, indexReg, out var cases, out var _))
                bestTargets = bestTargets.Take(Math.Max(1, Math.Min(bestTargets.Count, cases))).ToList();
            targets = bestTargets;
            mode = bestMode switch
            {
                "csbase" => "enc=cs:off",
                "rel" => "enc=rel",
                _ => "enc=abs",
            };
            return true;
        }

        private static void TryReadJumpTableEntries(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint tableBaseLinear, int max,
            out List<uint> entries, out List<uint> raw, out bool adjustedByBase)
        {
            TryReadJumpTableEntries(objects, objBytesByIndex, tableBaseLinear, max, stride: 4, entrySize: 4, out entries, out raw, out adjustedByBase);
        }

        private static void TryReadJumpTableEntries(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, uint tableBaseLinear, int max,
            int stride, int entrySize, out List<uint> entries, out List<uint> raw, out bool adjustedByBase)
        {
            entries = new List<uint>();
            raw = new List<uint>();
            adjustedByBase = false;
            if (tableBaseLinear == 0)
                return;
            if (stride <= 0)
                return;
            if (entrySize != 2 && entrySize != 4)
                return;
            if (!TryMapLinearToObject(objects, tableBaseLinear, out var tobj, out var toff))
                return;
            if (!objBytesByIndex.TryGetValue(tobj, out var tgtBytes) || tgtBytes == null)
                return;

            var baseAdjust = objects != null && tobj > 0 && tobj - 1 < objects.Count ? objects[tobj - 1].BaseAddress : 0u;
            for (var i = 0; i < max; i++)
            {
                var off = (int)toff + i * stride;
                if (off + entrySize > tgtBytes.Length)
                    break;
                uint v;
                if (entrySize == 2)
                {
                    v = (uint)(tgtBytes[off] | (tgtBytes[off + 1] << 8));
                }
                else
                {
                    v = (uint)(tgtBytes[off] | (tgtBytes[off + 1] << 8) | (tgtBytes[off + 2] << 16) | (tgtBytes[off + 3] << 24));
                }
                raw.Add(v);
                var cand = v;
                if (!TryMapLinearToObject(objects, cand, out var _tmpObj, out var _tmpOff))
                {
                    var adjusted = baseAdjust + cand;
                    if (!TryMapLinearToObject(objects, adjusted, out var _tmpObj2, out var _tmpOff2))
                        break;
                    cand = adjusted;
                    adjustedByBase = true;
                }
                entries.Add(cand);
            }
        }

        internal static bool TryParseIndirectJmpTable(byte[] bytes, out uint disp32, out string indexReg, out int scale)
        {
            return TryParseIndirectJmpTable(bytes, out disp32, out _, out indexReg, out scale, out _, out _);
        }

        private static bool TryParseIndirectJmpTable(
            byte[] bytes,
            out uint dispU32,
            out string baseReg,
            out string indexReg,
            out int scale,
            out int dispSigned,
            out bool addressSizeOverride)
        {
            dispU32 = 0;
            baseReg = string.Empty;
            indexReg = string.Empty;
            scale = 0;
            dispSigned = 0;
            addressSizeOverride = false;
            if (bytes == null)
                return false;

            // Skip common prefixes (segment override, rep, operand/address-size override, lock).
            var i = 0;
            while (i < bytes.Length)
            {
                var p = bytes[i];
                if (p == 0x67)
                    addressSizeOverride = true;
                if (p == 0x2E || p == 0x36 || p == 0x3E || p == 0x26 || p == 0x64 || p == 0x65 || p == 0x66 || p == 0x67 || p == 0xF0 || p == 0xF2 || p == 0xF3)
                {
                    i++;
                    continue;
                }
                break;
            }

            // We only support 32-bit addressing forms here (no 0x67).
            if (addressSizeOverride)
                return false;

            if (i + 2 >= bytes.Length)
                return false;
            if (bytes[i] != 0xFF)
                return false;

            var modrm = bytes[i + 1];
            var mod = (modrm >> 6) & 0x3;
            var reg = (modrm >> 3) & 0x7;
            var rm = modrm & 0x7;
            if (rm != 4)
                return false; // need SIB
            if (reg != 4)
                return false; // JMP r/m

            var sib = bytes[i + 2];
            var sibScale = (sib >> 6) & 0x3;
            var sibIndex = (sib >> 3) & 0x7;
            var sibBase = sib & 0x7;

            scale = 1 << (int)sibScale;

            indexReg = sibIndex switch
            {
                0 => "eax",
                1 => "ecx",
                2 => "edx",
                3 => "ebx",
                4 => string.Empty, // no index
                5 => "ebp",
                6 => "esi",
                7 => "edi",
                _ => string.Empty,
            };

            baseReg = sibBase switch
            {
                0 => "eax",
                1 => "ecx",
                2 => "edx",
                3 => "ebx",
                4 => "esp",
                5 => mod == 0 ? string.Empty : "ebp", // mod==0 => disp32 only
                6 => "esi",
                7 => "edi",
                _ => string.Empty,
            };

            // Displacement comes after SIB; size depends on mod.
            var dispOff = i + 3;
            if (mod == 0)
            {
                if (sibBase == 5)
                {
                    if (dispOff + 4 > bytes.Length)
                        return false;
                    dispSigned = bytes[dispOff] | (bytes[dispOff + 1] << 8) | (bytes[dispOff + 2] << 16) | (bytes[dispOff + 3] << 24);
                    dispU32 = unchecked((uint)dispSigned);
                }
                else
                {
                    dispSigned = 0;
                    dispU32 = 0;
                }
            }
            else if (mod == 1)
            {
                if (dispOff + 1 > bytes.Length)
                    return false;
                dispSigned = unchecked((sbyte)bytes[dispOff]);
                dispU32 = unchecked((uint)dispSigned);
            }
            else if (mod == 2)
            {
                if (dispOff + 4 > bytes.Length)
                    return false;
                dispSigned = bytes[dispOff] | (bytes[dispOff + 1] << 8) | (bytes[dispOff + 2] << 16) | (bytes[dispOff + 3] << 24);
                dispU32 = unchecked((uint)dispSigned);
            }
            else
            {
                // mod==3 is register indirect; not a table
                return false;
            }

            return !string.IsNullOrWhiteSpace(indexReg) && scale != 0;
        }

        private static bool HasOperandSizeOverridePrefix(byte[] bytes)
        {
            if (bytes == null)
                return false;
            foreach (var b in bytes)
            {
                if (b == 0x66)
                    return true;
                // Stop scanning at opcode.
                if (!(b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3))
                    break;
            }
            return false;
        }

        private static bool TryGetJumpTableTargets(
            List<Instruction> instructions,
            Dictionary<uint, int> insIndexByAddr,
            int insIdx,
            Instruction ins,
            List<LEObject> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            int maxEntries,
            out uint tableBase,
            out string indexReg,
            out List<uint> targets)
        {
            tableBase = 0;
            indexReg = string.Empty;
            targets = null;
            if (ins?.Bytes == null)
                return false;
            if (!TryParseIndirectJmpTable(ins.Bytes, out var disp, out var reg, out var scale))
                return false;

            indexReg = reg;

            if (TryResolveJumpTableTargets(instructions, insIndexByAddr, insIdx, ins, objects, objBytesByIndex, maxEntries, out var baseResolved, out var resolvedTargets, out var _))
            {
                tableBase = baseResolved;
                targets = resolvedTargets;
                return true;
            }

            return false;
        }

        internal static bool TryInferJumpTableSwitchBound(List<Instruction> instructions, int jmpIdx, string indexReg, out int caseCount, out uint defaultTarget)
        {
            caseCount = 0;
            defaultTarget = 0;
            if (instructions == null || jmpIdx <= 0 || string.IsNullOrWhiteSpace(indexReg))
                return false;

            // Pattern (common):
            //   cmp <reg>, <imm>
            //   ja  <default>
            //   jmp [<reg>*4 + table]
            // Allow small gaps.
            for (var back = 1; back <= 6; back++)
            {
                var idx = jmpIdx - back;
                if (idx < 0)
                    break;

                var t = InsText(instructions[idx]).Trim();
                if (!t.StartsWith("cmp ", StringComparison.OrdinalIgnoreCase))
                    continue;

                var m = Regex.Match(
                    t,
                    @$"^cmp\s+{Regex.Escape(indexReg)}\s*,\s*(?:(?:byte|word|dword)\s+)?(?<imm>0x[0-9A-Fa-f]{{1,8}}|[0-9]+)\s*$",
                    RegexOptions.IgnoreCase);
                if (!m.Success)
                    continue;

                if (!TryParseHexUInt(m.Groups["imm"].Value, out var imm))
                    continue;

                // Find a following bounds-check jump between cmp and jmp.
                // Note: Disassemblers may render synonyms (e.g., jae == jnc == jnb).
                var inclusive = true;
                for (var fwd = idx + 1; fwd < jmpIdx && fwd <= idx + 3; fwd++)
                {
                    var jt = InsText(instructions[fwd]).Trim();
                    if (jt.StartsWith("ja ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jae ", StringComparison.OrdinalIgnoreCase) ||
                        jt.StartsWith("jg ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jge ", StringComparison.OrdinalIgnoreCase) ||
                        jt.StartsWith("jnc ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jnb ", StringComparison.OrdinalIgnoreCase))
                    {
                        // ja/jg => reg > imm ; valid cases: 0..imm (inclusive)
                        // jae/jge/jnc/jnb => reg >= imm ; valid cases: 0..imm-1 (exclusive)
                        inclusive = jt.StartsWith("ja ", StringComparison.OrdinalIgnoreCase) || jt.StartsWith("jg ", StringComparison.OrdinalIgnoreCase);
                        if (TryGetRelativeBranchTarget(instructions[fwd], out var target, out var isCall) && !isCall)
                            defaultTarget = target;
                        break;
                    }
                }

                if (imm < 0x10000)
                {
                    var cc = inclusive ? checked((int)imm + 1) : checked((int)imm);
                    if (cc > 0)
                    {
                        caseCount = cc;
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, bool leFixups, bool leGlobals, bool leInsights, out string output, out string error)
        {
            return TryDisassembleToString(inputFile, leFull, leBytesLimit, leRenderLimit: null, leJobs: 1, leFixups, leGlobals, leInsights, EnumToolchainHint.None, leStartLinear: null, out output, out error);
        }

        private static bool IsRegister32(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;
            switch (token.Trim().ToLowerInvariant())
            {
                case "eax":
                case "ebx":
                case "ecx":
                case "edx":
                case "esi":
                case "edi":
                case "ebp":
                case "esp":
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryParseImm32(string token, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(token))
                return false;

            var t = token.Trim();
            var m = Regex.Match(t, @"^0x(?<hex>[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
            if (!m.Success)
                return false;

            value = Convert.ToUInt32(m.Groups["hex"].Value, 16);
            return true;
        }

        private static bool TryResolveRegisterValueBefore(List<Instruction> instructions, int indexExclusive, string reg, out uint value, HashSet<uint> resourceGetterTargets = null)
        {
            value = 0;
            if (instructions == null || indexExclusive <= 0)
                return false;
            if (!IsRegister32(reg))
                return false;

            var start = Math.Min(indexExclusive - 1, instructions.Count - 1);
            var stop = Math.Max(0, start - 64);

            // Small forward constant-tracker across a short window.
            // This is intentionally conservative: it only tracks immediate constants and simple arithmetic.
            var known = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var vals = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in new[] { "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp" })
                known[r] = false;

            for (var i = stop; i <= start; i++)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                // Resource getter: best-effort propagate eax = base + id across detected helper calls.
                // We intentionally do not require that edx was tracked as a constant: instead we re-scan the
                // immediate window before the call for the typical (base,id) setup pattern.
                if (resourceGetterTargets != null && resourceGetterTargets.Count > 0)
                {
                    var mcall = Regex.Match(t, @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (mcall.Success && TryParseHexUInt(mcall.Groups["target"].Value, out var tgt) && resourceGetterTargets.Contains(tgt))
                    {
                        if (TryComputeResourceGetterReturn(instructions, i, out var derived))
                        {
                            known["eax"] = true;
                            vals["eax"] = derived;
                        }
                        continue;
                    }
                }

                // xor r, r => 0
                var mxor = Regex.Match(t, @"^xor\s+(?<r>e[a-z]{2}),\s*\k<r>$", RegexOptions.IgnoreCase);
                if (mxor.Success)
                {
                    var r0 = mxor.Groups["r"].Value.ToLowerInvariant();
                    known[r0] = true;
                    vals[r0] = 0;
                    continue;
                }

                // mov r, 0x...
                var mmovImm = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (mmovImm.Success)
                {
                    var dst = mmovImm.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(mmovImm.Groups["imm"].Value, out var imm))
                    {
                        known[dst] = true;
                        vals[dst] = imm;
                    }
                    continue;
                }

                // mov r, r
                var mmovReg = Regex.Match(t, @"^mov\s+(?<dst>e[a-z]{2}),\s*(?<src>e[a-z]{2})$", RegexOptions.IgnoreCase);
                if (mmovReg.Success)
                {
                    var dst = mmovReg.Groups["dst"].Value.ToLowerInvariant();
                    var src = mmovReg.Groups["src"].Value.ToLowerInvariant();
                    if (known.TryGetValue(src, out var srcKnown) && srcKnown && vals.TryGetValue(src, out var srcVal))
                    {
                        known[dst] = true;
                        vals[dst] = srcVal;
                    }
                    else
                    {
                        known[dst] = false;
                    }
                    continue;
                }

                // add r, 0x...
                var madd = Regex.Match(t, @"^add\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (madd.Success)
                {
                    var dst = madd.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(madd.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = unchecked(cur + imm);
                    }
                    continue;
                }

                // sub r, 0x...
                var msub = Regex.Match(t, @"^sub\s+(?<dst>e[a-z]{2}),\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (msub.Success)
                {
                    var dst = msub.Groups["dst"].Value.ToLowerInvariant();
                    if (TryParseImm32(msub.Groups["imm"].Value, out var imm) && known.TryGetValue(dst, out var dstKnown) && dstKnown && vals.TryGetValue(dst, out var cur))
                    {
                        vals[dst] = unchecked(cur - imm);
                    }
                    continue;
                }

                // lea r, [base+0xdisp] or lea r, [base+disp]
                var mlea = Regex.Match(t, @"^lea\s+(?<dst>e[a-z]{2}),\s*\[(?<base>e[a-z]{2})\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
                if (mlea.Success)
                {
                    var dst = mlea.Groups["dst"].Value.ToLowerInvariant();
                    var bas = mlea.Groups["base"].Value.ToLowerInvariant();
                    var disp = Convert.ToUInt32(mlea.Groups["disp"].Value, 16);
                    if (known.TryGetValue(bas, out var baseKnown) && baseKnown && vals.TryGetValue(bas, out var baseVal))
                    {
                        known[dst] = true;
                        vals[dst] = unchecked(baseVal + disp);
                    }
                    else
                    {
                        known[dst] = false;
                    }
                    continue;
                }
            }

            var rr = reg.Trim().ToLowerInvariant();
            if (known.TryGetValue(rr, out var k) && k && vals.TryGetValue(rr, out var v))
            {
                value = v;
                return true;
            }

            return false;
        }

        private static bool TryComputeResourceGetterReturn(List<Instruction> instructions, int callIdx, out uint value)
        {
            value = 0;
            if (instructions == null || callIdx <= 0 || callIdx >= instructions.Count)
                return false;

            uint? offsetImm = null;
            uint? regionBase = null;

            for (var i = callIdx - 1; i >= 0 && i >= callIdx - 12; i--)
            {
                var t = InsText(instructions[i]).Trim();
                if (string.IsNullOrEmpty(t))
                    continue;

                // Stop at control-flow barriers
                if (t.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || t.StartsWith("ret", StringComparison.OrdinalIgnoreCase) ||
                    t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase) || (t.StartsWith("j", StringComparison.OrdinalIgnoreCase) && !t.StartsWith("jmp", StringComparison.OrdinalIgnoreCase)))
                {
                    break;
                }

                // id: mov eax, 0xNNNN (small)
                var mo = Regex.Match(t, @"^mov\s+eax,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (offsetImm == null && mo.Success && TryParseImm32(mo.Groups["imm"].Value, out var oi) && oi < 0x10000)
                {
                    offsetImm = oi;
                    continue;
                }

                // base: add edx, 0xE0000 (or similar)
                var ma = Regex.Match(t, @"^add\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && ma.Success && TryParseImm32(ma.Groups["imm"].Value, out var rb) && rb >= 0x10000)
                {
                    regionBase = rb;
                    continue;
                }

                // base: mov edx, 0xE0000
                var mm = Regex.Match(t, @"^mov\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (regionBase == null && mm.Success && TryParseImm32(mm.Groups["imm"].Value, out var rb2) && rb2 >= 0x10000)
                {
                    regionBase = rb2;
                    continue;
                }

                // base: lea edx, [<reg>+0xE0000]
                var ml = Regex.Match(t, @"^lea\s+edx,\s*\[e[a-z]{2}\+0x(?<disp>[0-9a-fA-F]+)\]$", RegexOptions.IgnoreCase);
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
                return false;

            // Keep it conservative: common DOS4GW resource region patterns
            var rbv = regionBase.Value;
            if (!(rbv >= 0x000C0000 && rbv <= 0x000F0000 && (rbv % 0x10000 == 0)))
                return false;

            value = unchecked(rbv + offsetImm.Value);
            return true;
        }

        private static HashSet<uint> DetectResourceGetterTargets(List<Instruction> instructions)
        {
            var result = new HashSet<uint>();
            if (instructions == null || instructions.Count == 0)
                return result;

            var counts = new Dictionary<uint, int>();

            for (var i = 0; i < instructions.Count; i++)
            {
                var t = InsText(instructions[i]).Trim();
                var mcall = Regex.Match(t, @"^call\s+(?<target>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                if (!mcall.Success)
                    continue;

                if (!TryParseHexUInt(mcall.Groups["target"].Value, out var tgt))
                    continue;

                uint? id = null;
                uint? baseImm = null;

                for (var k = i - 1; k >= 0 && k >= i - 10; k--)
                {
                    var back = InsText(instructions[k]).Trim();
                    if (back.StartsWith("call ", StringComparison.OrdinalIgnoreCase) || back.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                        break;

                    var mmov = Regex.Match(back, @"^mov\s+eax,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (id == null && mmov.Success && TryParseHexUInt(mmov.Groups["imm"].Value, out var vi) && vi < 0x2000)
                    {
                        id = vi;
                        continue;
                    }

                    var madd = Regex.Match(back, @"^add\s+edx,\s*(?<imm>0x[0-9a-fA-F]{1,8})$", RegexOptions.IgnoreCase);
                    if (baseImm == null && madd.Success && TryParseHexUInt(madd.Groups["imm"].Value, out var vb) && vb >= 0x000C0000 && vb <= 0x000F0000 && (vb % 0x10000 == 0))
                    {
                        baseImm = vb;
                        continue;
                    }
                }

                if (id.HasValue && baseImm.HasValue)
                {
                    if (!counts.ContainsKey(tgt))
                        counts[tgt] = 0;
                    counts[tgt]++;
                }
            }

            foreach (var kvp in counts)
            {
                // Threshold: show up in multiple places before we treat it as a helper.
                if (kvp.Value >= 3)
                    result.Add(kvp.Key);
            }

            return result;
        }

        private static bool LooksLikePrintfFormat(string s)
        {
            if (string.IsNullOrEmpty(s))
                return false;

            // Basic heuristic: contains a % that isn't only %%
            for (var i = 0; i < s.Length - 1; i++)
            {
                if (s[i] != '%')
                    continue;
                if (s[i + 1] == '%')
                {
                    i++;
                    continue;
                }

                // Skip flags/width/precision
                var j = i + 1;
                while (j < s.Length && "-+ #0".IndexOf(s[j]) >= 0) j++;
                while (j < s.Length && char.IsDigit(s[j])) j++;
                if (j < s.Length && s[j] == '.')
                {
                    j++;
                    while (j < s.Length && char.IsDigit(s[j])) j++;
                }

                if (j < s.Length)
                {
                    var c = s[j];
                    if ("duxXscpfegEGi".IndexOf(c) >= 0)
                        return true;
                }
            }

            return false;
        }

        private static Dictionary<uint, string> CollectGlobalSymbols(List<Instruction> instructions, List<LEFixup> sortedFixups)
        {
            var globals = new Dictionary<uint, string>();
            if (instructions == null || sortedFixups == null || sortedFixups.Count == 0)
                return globals;

            var idx = 0;
            foreach (var ins in instructions)
            {
                var fixupsHere = GetFixupsForInstruction(sortedFixups, ins, ref idx);
                foreach (var f in fixupsHere)
                {
                    // Only globalize memory absolute displacements.
                    if (!f.Value32.HasValue || !f.TargetObject.HasValue)
                        continue;
                    var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                    if (!TryClassifyFixupKind(ins, delta, out var kind) || kind != "disp32")
                        continue;

                    var addr = f.Value32.Value;
                    if (!globals.ContainsKey(addr))
                        globals[addr] = $"g_{addr:X8}";
                }
            }

            return globals;
        }

        private static string ApplyGlobalSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> globals)
        {
            if (string.IsNullOrEmpty(insText) || fixupsHere == null || fixupsHere.Count == 0 || globals == null || globals.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!f.Value32.HasValue || !globals.TryGetValue(f.Value32.Value, out var sym))
                    continue;

                var delta = unchecked((int)(f.SiteLinear - (uint)ins.Offset));
                if (!TryClassifyFixupKind(ins, delta, out var kind) || kind != "disp32")
                    continue;

                // SharpDisasm tends to render these as 0x????? (lowercase hex). Replace both just in case.
                var needleLower = $"0x{f.Value32.Value:x}";
                var needleUpper = $"0x{f.Value32.Value:X}";
                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }

        private static List<LEFixup> GetFixupsForInstruction(List<LEFixup> fixups, Instruction ins, ref int idx)
        {
            if (fixups == null || fixups.Count == 0 || ins == null)
                return new List<LEFixup>(0);

            var insStart = (uint)ins.Offset;
            var insEnd = unchecked((uint)(insStart + (uint)ins.Length));

            // Advance past fixups that are below this instruction.
            while (idx < fixups.Count && fixups[idx].SiteLinear < insStart)
                idx++;

            if (idx >= fixups.Count)
                return new List<LEFixup>(0);

            var hit = new List<LEFixup>();
            var scan = idx;
            while (scan < fixups.Count)
            {
                var f = fixups[scan];
                if (f.SiteLinear >= insEnd)
                    break;
                hit.Add(f);
                scan++;
            }

            return hit;
        }

        private static string FormatFixupAnnotation(Instruction ins, List<LEFixup> fixupsHere, List<LEObject> objects)
        {
            if (fixupsHere == null || fixupsHere.Count == 0 || ins == null)
                return string.Empty;

            var insStart = (uint)ins.Offset;
            var parts = new List<string>();

            foreach (var f in fixupsHere)
            {
                var delta = unchecked((int)(f.SiteLinear - insStart));
                var kind = TryClassifyFixupKind(ins, delta, out var k) ? k : "unk";

                var mapped = string.Empty;
                if (f.TargetObject.HasValue && f.TargetOffset.HasValue)
                {
                    mapped = $" => obj{f.TargetObject.Value}+0x{f.TargetOffset.Value:X}";
                    if (objects != null)
                    {
                        var oi = objects.FindIndex(o => o.Index == (uint)f.TargetObject.Value);
                        if (oi >= 0)
                        {
                            var linear = objects[oi].BaseAddress + (ulong)f.TargetOffset.Value;
                            mapped += $" (linear 0x{linear:X8})";
                        }
                    }
                }

                var v32 = f.Value32.HasValue ? $" val32=0x{f.Value32.Value:X8}" : string.Empty;

                parts.Add($"{kind} site+{delta} type=0x{f.Type:X2} flags=0x{f.Flags:X2}{v32}{mapped}");
            }

            if (parts.Count == 0)
                return string.Empty;

            var distinct = parts.Distinct().ToList();
            const int maxShown = 3;
            if (distinct.Count <= maxShown)
                return string.Join(" | ", distinct);

            return string.Join(" | ", distinct.Take(maxShown)) + $" | (+{distinct.Count - maxShown} more)";
        }

        private static bool TryClassifyFixupKind(Instruction ins, int fixupDelta, out string kind)
        {
            kind = string.Empty;

            if (ins?.Bytes == null || ins.Bytes.Length == 0)
                return false;
            if (fixupDelta < 0 || fixupDelta >= ins.Bytes.Length)
                return false;

            var b = ins.Bytes;

            // Skip common prefixes
            var p = 0;
            while (p < b.Length)
            {
                var x = b[p];
                // operand-size, address-size, rep/lock, segment overrides
                if (x == 0x66 || x == 0x67 || x == 0xF0 || x == 0xF2 || x == 0xF3 ||
                    x == 0x2E || x == 0x36 || x == 0x3E || x == 0x26 || x == 0x64 || x == 0x65)
                {
                    p++;
                    continue;
                }
                break;
            }

            if (p >= b.Length)
                return false;

            var op0 = b[p];

            // MOV moffs: A0-A3 (disp32 right after opcode in 32-bit addr mode)
            if (op0 >= 0xA0 && op0 <= 0xA3)
            {
                var dispOff = p + 1;
                if (fixupDelta == dispOff)
                {
                    kind = "disp32";
                    return true;
                }
            }

            // Two-byte opcodes
            var opLen = 1;
            byte op1 = 0;
            if (op0 == 0x0F)
            {
                if (p + 1 >= b.Length)
                    return false;
                op1 = b[p + 1];
                opLen = 2;
            }

            var opIndexEnd = p + opLen;
            if (opIndexEnd >= b.Length)
                return false;

            // Patterns with ModRM + disp32 + immediate (very common in DOS4GW code)
            // 80/81/83 grp1, C6/C7 mov r/m, imm
            if (op0 == 0x80 || op0 == 0x81 || op0 == 0x83 || op0 == 0xC6 || op0 == 0xC7)
            {
                var modrmIndex = opIndexEnd;
                var modrm = b[modrmIndex];
                var mod = (modrm >> 6) & 0x3;
                var rm = modrm & 0x7;

                // Only handle the simple disp32 form: mod=00 rm=101 (no SIB)
                if (mod == 0 && rm == 5)
                {
                    var dispOff = modrmIndex + 1;
                    var afterDisp = dispOff + 4;

                    if (fixupDelta == dispOff)
                    {
                        kind = "disp32";
                        return true;
                    }

                    // Immediate offset depends on opcode.
                    if (op0 == 0x81 || op0 == 0xC7)
                    {
                        if (fixupDelta == afterDisp)
                        {
                            kind = "imm32";
                            return true;
                        }
                    }
                    else if (op0 == 0x80 || op0 == 0x83 || op0 == 0xC6)
                    {
                        if (fixupDelta == afterDisp)
                        {
                            kind = "imm8";
                            return true;
                        }
                    }
                }
            }

            // Common reg/mem ops with disp32 only (no immediate): 8B/89/8D, etc.
            if (op0 == 0x8B || op0 == 0x89 || op0 == 0x8D)
            {
                var modrmIndex = opIndexEnd;
                if (modrmIndex < b.Length)
                {
                    var modrm = b[modrmIndex];
                    var mod = (modrm >> 6) & 0x3;
                    var rm = modrm & 0x7;
                    if (mod == 0 && rm == 5)
                    {
                        var dispOff = modrmIndex + 1;
                        if (fixupDelta == dispOff)
                        {
                            kind = "disp32";
                            return true;
                        }
                    }
                }
            }

            // Fallback heuristic: if fixup hits the last 4 bytes, it’s likely an imm32 or disp32.
            if (ins.Bytes.Length >= 4 && fixupDelta == ins.Bytes.Length - 4)
            {
                kind = "imm32?";
                return true;
            }

            return false;
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
                return TryFindLEHeaderOffset(fileBytes, allowMzOverlayScanFallback: false, out offset);
            }

            private static bool TryFindLEHeaderOffset(byte[] fileBytes, bool allowMzOverlayScanFallback, out int offset)
            {
                offset = 0;
                if (fileBytes == null || fileBytes.Length < 0x40)
                    return false;

                // First: if this is an MZ container, prefer e_lfanew.
                // This avoids false positives where an "LE\0\0" byte sequence appears in the stub or data.
                var isMz = fileBytes[0] == (byte)'M' && fileBytes[1] == (byte)'Z';
                if (isMz)
                {
                    var lfanew = (int)ReadUInt32(fileBytes, 0x3C);
                    var lfanewLooksInvalid = lfanew <= 0 || lfanew + 4 > fileBytes.Length;
                    if (!lfanewLooksInvalid)
                    {
                        if (fileBytes[lfanew] == (byte)'L' && fileBytes[lfanew + 1] == (byte)'E' && fileBytes[lfanew + 2] == 0x00 &&
                            fileBytes[lfanew + 3] == 0x00)
                        {
                            if (TryParseHeader(fileBytes, lfanew, out var _, out var _))
                            {
                                offset = lfanew;
                                return true;
                            }
                        }
                    }

                    // Next: handle BW overlay containers (EURO96/EUROBLST-style), where the *real* bound MZ+LE lives
                    // behind a BW overlay header and e_lfanew may be bogus/out-of-range.
                    if (TryFindEmbeddedLeOffsetFromBwOverlay(fileBytes, out var bwLeOffset) &&
                        TryParseHeader(fileBytes, bwLeOffset, out var _, out var _))
                    {
                        offset = bwLeOffset;
                        return true;
                    }

                    // Constrained fallback scan *only* in the overlay region.
                    // - If explicitly enabled, always try.
                    // - If e_lfanew is clearly bogus/out-of-range, try automatically (real-world DOS4GW stubs exist like this).
                    if ((allowMzOverlayScanFallback || lfanewLooksInvalid) &&
                        TryScanForLeHeaderInMzOverlay(fileBytes, out var scanOffset))
                    {
                        offset = scanOffset;
                        return true;
                    }

                    // Default behavior: do NOT scan inside MZ containers.
                    offset = 0;
                    return false;
                }

                // Fallback: scan for a plausible LE signature and validate by parsing.
                // (Used for raw LE images without an MZ container.)
                for (var i = 0; i <= fileBytes.Length - 4; i++)
                {
                    if (fileBytes[i] != (byte)'L' || fileBytes[i + 1] != (byte)'E' || fileBytes[i + 2] != 0x00 || fileBytes[i + 3] != 0x00)
                        continue;

                    if (TryParseHeader(fileBytes, i, out var _, out var _))
                    {
                        offset = i;
                        return true;
                    }
                }

                offset = 0;
                return false;
            }

            private static bool TryScanForLeHeaderInMzOverlay(byte[] fileBytes, out int leHeaderOffset)
            {
                leHeaderOffset = 0;
                if (fileBytes == null || fileBytes.Length < 0x40)
                    return false;
                if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
                    return false;

                // Compute the overlay base (load module size) from the outer MZ header.
                // This intentionally avoids scanning the MZ stub body.
                var eCblp = ReadUInt16(fileBytes, 0x02);
                var eCp = ReadUInt16(fileBytes, 0x04);
                if (eCp == 0)
                    return false;

                var overlayBaseL = ((long)eCp - 1) * 512L + (eCblp == 0 ? 512L : eCblp);
                if (overlayBaseL < 0x40 || overlayBaseL >= fileBytes.Length)
                    return false;
	
                var start = (int)overlayBaseL;
                for (var i = start; i <= fileBytes.Length - 4; i++)
                {
                    if (fileBytes[i] != (byte)'L' || fileBytes[i + 1] != (byte)'E' || fileBytes[i + 2] != 0x00 || fileBytes[i + 3] != 0x00)
                        continue;

                    if (TryParseHeader(fileBytes, i, out var _, out var _))
                    {
                        leHeaderOffset = i;
                        return true;
                    }
                }

                return false;
            }

	        private static bool TryFindEmbeddedLeOffsetFromBwOverlay(byte[] fileBytes, out int leHeaderOffset)
	        {
	            leHeaderOffset = 0;
	            if (fileBytes == null || fileBytes.Length < 0x40)
	                return false;
	            if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
	                return false;

	            // Compute the overlay base (load module size) from the outer MZ header.
	            var eCblp = ReadUInt16(fileBytes, 0x02);
	            var eCp = ReadUInt16(fileBytes, 0x04);
	            if (eCp == 0)
	                return false;

	            var overlayBaseL = ((long)eCp - 1) * 512L + (eCblp == 0 ? 512L : eCblp);
	            if (overlayBaseL < 0x40 || overlayBaseL + 4 > fileBytes.Length)
	                return false;
	            var overlayBase = (int)overlayBaseL;

	            // BW overlay header signature.
	            if (fileBytes[overlayBase] != (byte)'B' || fileBytes[overlayBase + 1] != (byte)'W')
	                return false;

	            var bwHeaderLen = (int)ReadUInt16(fileBytes, overlayBase + 2);
	            if (bwHeaderLen <= 0 || bwHeaderLen > 64 * 1024)
	                return false;
	            if (overlayBase + bwHeaderLen > fileBytes.Length)
	                return false;

	            // Heuristic: scan BW header u32 fields for a relative pointer to an embedded MZ which itself is bound to LE.
	            for (var fieldOff = 0; fieldOff + 4 <= bwHeaderLen; fieldOff += 4)
	            {
	                var rel = ReadUInt32(fileBytes, overlayBase + fieldOff);
	                if (rel == 0)
	                    continue;

	                var innerMzOffL = overlayBaseL + rel;
	                if (innerMzOffL < 0 || innerMzOffL + 0x40 > fileBytes.Length)
	                    continue;
	                var innerMzOff = (int)innerMzOffL;

	                if (fileBytes[innerMzOff] != (byte)'M' || fileBytes[innerMzOff + 1] != (byte)'Z')
	                    continue;

	                var innerLfanew = ReadUInt32(fileBytes, innerMzOff + 0x3C);
	                if (innerLfanew < 0x40)
	                    continue;

	                var innerLeOffL = innerMzOffL + innerLfanew;
	                if (innerLeOffL < 0 || innerLeOffL + 4 > fileBytes.Length)
	                    continue;
	                var innerLeOff = (int)innerLeOffL;

	                if (fileBytes[innerLeOff] == (byte)'L' &&
	                    fileBytes[innerLeOff + 1] == (byte)'E' &&
	                    fileBytes[innerLeOff + 2] == 0x00 &&
	                    fileBytes[innerLeOff + 3] == 0x00)
	                {
	                    leHeaderOffset = innerLeOff;
	                    return true;
	                }
	            }

	            return false;
	        }

	        private static bool TryParseHeader(byte[] fileBytes, int headerOffset, out LEHeader header, out string error)
	        {
	            header = default;
	            error = string.Empty;

            if (headerOffset < 0 || headerOffset + 0x84 > fileBytes.Length)
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

        private static bool TryMapLinearToObject(List<LEObject> objects, uint linear, out int objIndex, out uint offset)
        {
            objIndex = 0;
            offset = 0;

            if (objects == null || objects.Count == 0)
                return false;

            // Objects are typically few (here: 3), so linear scan is fine.
            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0)
                    continue;

                // Allow a small slack for references that land in padding past VirtualSize.
                var end = unchecked(obj.BaseAddress + obj.VirtualSize + 0x1000);
                if (linear >= obj.BaseAddress && linear < end)
                {
                    objIndex = obj.Index;
                    offset = unchecked(linear - obj.BaseAddress);
                    return true;
                }
            }

            return false;
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

        private static string HexDump(byte[] data, int offset, int length, int bytesPerLine = 16)
        {
            if (data == null || length <= 0)
                return string.Empty;

            var sb = new StringBuilder();
            var end = Math.Min(data.Length, offset + length);
            for (var i = offset; i < end; i += bytesPerLine)
            {
                var lineLen = Math.Min(bytesPerLine, end - i);
                sb.Append(";   ");
                sb.Append($"0x{(i - offset):X4}: ");
                for (var j = 0; j < lineLen; j++)
                {
                    sb.Append(data[i + j].ToString("X2"));
                    if (j + 1 < lineLen)
                        sb.Append(' ');
                }
                sb.AppendLine();
            }
            return sb.ToString().TrimEnd();
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

        private static string TryAnnotateFcb(uint? linearAddr, Dictionary<uint, string> stringSymbols, List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex)
        {
            if (!linearAddr.HasValue) return string.Empty;

            foreach (var obj in objects)
            {
                if (linearAddr >= obj.RelocBaseAddr && linearAddr < obj.RelocBaseAddr + obj.VirtualSize)
                {
                    if (objBytesByIndex.TryGetValue(obj.ObjectNumber, out var bytes))
                    {
                        uint relativeOffset = linearAddr.Value - obj.RelocBaseAddr;
                        if (relativeOffset + 12 <= bytes.Length)
                        {
                            return MZDisassembler.TryFormatFcbDetail(relativeOffset, bytes);
                        }
                    }
                    break;
                }
            }

            return string.Empty;
        }
    }
}
