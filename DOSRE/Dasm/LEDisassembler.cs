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

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, bool leFixups, bool leGlobals, bool leInsights, out string output, out string error)
        {
            return TryDisassembleToString(inputFile, leFull, leBytesLimit, leRenderLimit: null, leJobs: 1, leFixups, leGlobals, leInsights, EnumToolchainHint.None, leStartLinear: null, out output, out error);
        }
    }
}
