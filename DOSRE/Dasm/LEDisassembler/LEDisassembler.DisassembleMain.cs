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
    public static partial class LEDisassembler
    {
        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, bool leFixups, bool leGlobals, bool leInsights, EnumToolchainHint toolchainHint, out string output, out string error)
        {
            return TryDisassembleToString(inputFile, leFull, leBytesLimit, leRenderLimit: null, leJobs: 1, leFixups, leGlobals, leInsights, toolchainHint, leStartLinear: null, out output, out error);
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, int? leRenderLimit, bool leFixups, bool leGlobals, bool leInsights, EnumToolchainHint toolchainHint, out string output, out string error)
        {
            return TryDisassembleToString(inputFile, leFull, leBytesLimit, leRenderLimit, leJobs: 1, leFixups, leGlobals, leInsights, toolchainHint, leStartLinear: null, out output, out error);
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, int? leRenderLimit, int leJobs, bool leFixups, bool leGlobals, bool leInsights, EnumToolchainHint toolchainHint, uint? leStartLinear, out string output, out string error)
        {
            return TryDisassembleToString(inputFile, leFull, leBytesLimit, leRenderLimit, leJobs, leFixups, leGlobals, leInsights, toolchainHint, leStartLinear, leScanMzOverlayFallback: false, out output, out error);
        }

        public static bool TryDisassembleToString(string inputFile, bool leFull, int? leBytesLimit, int? leRenderLimit, int leJobs, bool leFixups, bool leGlobals, bool leInsights, EnumToolchainHint toolchainHint, uint? leStartLinear, bool leScanMzOverlayFallback, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;

            // Avoid returning stale analysis from a prior run.
            SetLastAnalysis(null);

            var swTotal = Stopwatch.StartNew();

            if (!File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

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
            var analysis = leInsights
                ? new LeAnalysis { InputFile = inputFile, EntryLinear = entryLinear }
                : null;

            if (analysis != null)
            {
                var entryPoints = ParseEntryPoints(fileBytes, header, objects);
                foreach (var kvp in header.Exports)
                {
                    if (kvp.Key != 0 && entryPoints.TryGetValue(kvp.Key, out var addr))
                    {
                        analysis.ExportedNames[addr] = kvp.Value;
                    }
                }
            }

            List<string> importModules = null;
            byte[] fixupRecordStream = null;
            uint[] fixupPageOffsets = null;

            if (leFixups || leGlobals)
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
            AppendWrappedDisasmLine(sb, string.Empty, $" ; Disassembly of {Path.GetFileName(inputFile)} (LE / DOS4GW)", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, $" ; PageSize: {header.PageSize}  LastPageSize: {header.LastPageSize}  Pages: {header.NumberOfPages}", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, $" ; Entry: Obj {header.EntryEipObject} + 0x{header.EntryEip:X} (Linear 0x{entryLinearU:X})", commentColumn: 0, maxWidth: 160);
            if (toolchainHint != EnumToolchainHint.None)
            {
                AppendWrappedDisasmLine(sb, string.Empty, $" ; Toolchain hint: {toolchainHint}", commentColumn: 0, maxWidth: 160);

                var markers = FindToolchainMarkers(fileBytes, toolchainHint, 12);
                if (markers.Count > 0)
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Toolchain markers (best-effort)", commentColumn: 0, maxWidth: 160);
                    foreach (var m in markers.OrderBy(m => m.Offset))
                        AppendWrappedDisasmLine(sb, string.Empty, $" ; 0x{m.Offset:X}  {m.Text}", commentColumn: 0, maxWidth: 160);
                }
                else
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Toolchain markers (best-effort): none found", commentColumn: 0, maxWidth: 160);
                }
            }
            if (leFixups)
                AppendWrappedDisasmLine(sb, string.Empty, " ; NOTE: LE fixup annotations enabled (best-effort)", commentColumn: 0, maxWidth: 160);
            else
                AppendWrappedDisasmLine(sb, string.Empty, " ; NOTE: Minimal LE support (no fixups/import analysis)", commentColumn: 0, maxWidth: 160);

            if (leGlobals)
                AppendWrappedDisasmLine(sb, string.Empty, " ; NOTE: LE globals enabled (disp32 fixups become g_XXXXXXXX symbols)", commentColumn: 0, maxWidth: 160);
            if (leInsights)
                AppendWrappedDisasmLine(sb, string.Empty, " ; NOTE: LE insights enabled (best-effort function/CFG/xref/stack-var/string analysis)", commentColumn: 0, maxWidth: 160);
            if (leInsights)
                AppendWrappedDisasmLine(sb, string.Empty, $" ; NOTE: LE insights jobs: {Math.Max(1, leJobs)}", commentColumn: 0, maxWidth: 160);
            if (leRenderLimit.HasValue)
            {
                if (leRenderLimit.Value == 0)
                    AppendWrappedDisasmLine(sb, string.Empty, " ; NOTE: LE render disabled (-lerenderlimit 0): insights-only output (no instruction listing)", commentColumn: 0, maxWidth: 160);
                else
                    AppendWrappedDisasmLine(sb, string.Empty, $" ; NOTE: LE render limit enabled: {leRenderLimit.Value} instructions/object", commentColumn: 0, maxWidth: 160);
            }
            AppendWrappedDisasmLine(sb, string.Empty, " ; XREFS: derived from relative CALL/JMP/Jcc only", commentColumn: 0, maxWidth: 160);
            if (leFull)
                AppendWrappedDisasmLine(sb, string.Empty, " ; LE mode: FULL (disassemble from object start)", commentColumn: 0, maxWidth: 160);
            if (!leFull && leBytesLimit.HasValue)
                AppendWrappedDisasmLine(sb, string.Empty, $" ; LE mode: LIMIT {leBytesLimit.Value} bytes", commentColumn: 0, maxWidth: 160);
            sb.AppendLine(";");

            AppendWrappedDisasmLine(sb, string.Empty, " ; Legend:", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, " ;   func_XXXXXXXX: function entry (best-effort)", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, " ;   loc_XXXXXXXX: local label (branch/jump target)", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, " ;   bb_XXXXXXXX: basic block label (CFG)", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, " ;   CALLHINT: heuristic call signature (args~/ret=)", commentColumn: 0, maxWidth: 160);
            AppendWrappedDisasmLine(sb, string.Empty, " ;   FIXUP: kind site+N type/flags val32 => objK+off (linear 0x........) (best-effort)", commentColumn: 0, maxWidth: 160);
            sb.AppendLine(";");

            // Reconstruct all object bytes once so we can scan data objects (strings) and map xrefs.
            var swObjRebuild = Stopwatch.StartNew();
            _logger.Info("LE: Reconstructing object bytes...");
            var objBytesByIndex = new Dictionary<int, byte[]>();
            long objBytesTotal = 0;
            foreach (var o in objects)
            {
                if (o.VirtualSize == 0 || o.PageCount == 0)
                    continue;
                var bytes = ReconstructObjectBytes(fileBytes, header, pageMap, dataPagesBase, o);
                if (bytes != null && bytes.Length > 0)
                {
                    objBytesByIndex[o.Index] = bytes;
                    objBytesTotal += bytes.Length;
                }
            }
            _logger.Info($"LE: Reconstructed {objBytesByIndex.Count}/{objects.Count} objects ({objBytesTotal} bytes) in {swObjRebuild.ElapsedMilliseconds} ms");

            // String symbol table (linear address -> symbol)
            Dictionary<uint, string> stringSymbols = null;
            Dictionary<uint, string> stringPreview = null;
            Dictionary<uint, string> resourceSymbols = null;
            Dictionary<uint, string> vtblSymbols = null;
            Dictionary<uint, Dictionary<uint, uint>> vtblSlots = null;
            Dictionary<uint, string> dispatchTableNotes = null;
            Dictionary<uint, string> dispatchTableSymbols = null;
            if (leInsights)
            {
                var swStrings = Stopwatch.StartNew();
                _logger.Info("LE: Scanning strings (insights)...");
                ScanStrings(objects, objBytesByIndex, out stringSymbols, out stringPreview);
                _logger.Info($"LE: String scan complete: {stringSymbols?.Count ?? 0} strings in {swStrings.ElapsedMilliseconds} ms");
                resourceSymbols = new Dictionary<uint, string>();
                vtblSymbols = new Dictionary<uint, string>();
                vtblSlots = new Dictionary<uint, Dictionary<uint, uint>>();
                dispatchTableNotes = new Dictionary<uint, string>();
                dispatchTableSymbols = new Dictionary<uint, string>();
                if (stringSymbols.Count > 0)
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Strings (best-effort, ASCII/CP437-ish)", commentColumn: 0, maxWidth: 160);
                    foreach (var kvp in stringSymbols.OrderBy(k => k.Key).Take(512))
                    {
                        var prev = stringPreview.TryGetValue(kvp.Key, out var p) ? p : string.Empty;
                        if (!string.IsNullOrEmpty(prev))
                            AppendWrappedDisasmLine(sb, string.Empty, $"{kvp.Value} EQU 0x{kvp.Key:X8} ; \"{prev}\"", commentColumn: 40, maxWidth: 160);
                        else
                            sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8}");
                    }
                    if (stringSymbols.Count > 512)
                        AppendWrappedDisasmLine(sb, string.Empty, $" ; (strings truncated: {stringSymbols.Count} total)", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine(";");
                }
            }

            // Global symbol table (linear address -> symbol) from fixups
            var leGlobalSymbols = new Dictionary<uint, string>();
            var globalFixupTargets = new HashSet<uint>();
            if (fixupRecordStream != null && fixupPageOffsets != null)
            {
                var swGlob = Stopwatch.StartNew();
                _logger.Info("LE: Collecting global symbols and targets from fixup table...");
                foreach (var obj in objects)
                {
                    if (obj.VirtualSize == 0 || obj.PageCount == 0) continue;
                    // Pass null for objBytes to just get targets from the record stream without site probing.
                    var gFixups = ParseFixupsForWindow(header, objects, pageMap, importModules, fileBytes, fixupPageOffsets, fixupRecordStream, null, obj, 0, uint.MaxValue);
                    foreach (var f in gFixups)
                    {
                        if ((f.TargetType == 0 || f.TargetType == 3) && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                        {
                            var targetObj = objects.FirstOrDefault(o => o.Index == f.TargetObject.Value);
                            if (targetObj.Index != 0)
                            {
                                var targetLinear = unchecked(targetObj.BaseAddress + f.TargetOffset.Value);
                                if (targetLinear != 0)
                                {
                                    globalFixupTargets.Add(targetLinear);
                                    if (leGlobals && !leGlobalSymbols.ContainsKey(targetLinear))
                                    {
                                        // Use a self-describing linear-address symbol so downstream decompile output can
                                        // define it as a simple numeric constant without needing an object-base mapping.
                                        // This also matches the documented -LEGLOBALS intent (g_XXXXXXXX EQU 0xXXXXXXXX).
                                        leGlobalSymbols[targetLinear] = $"g_{targetLinear:X8}";
                                    }
                                }
                            }
                        }
                    }
                }
                _logger.Info($"LE: Global symbols complete: {leGlobalSymbols.Count} symbols in {swGlob.ElapsedMilliseconds} ms");

                if (leGlobalSymbols.Count > 0)
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Global Symbols (from fixups)", commentColumn: 0, maxWidth: 160);
                    foreach (var kvp in leGlobalSymbols.OrderBy(k => k.Key).Take(512))
                    {
                        AppendWrappedDisasmLine(sb, string.Empty, $"{kvp.Value} EQU 0x{kvp.Key:X8}", commentColumn: 40, maxWidth: 160);
                    }
                    if (leGlobalSymbols.Count > 512)
                        AppendWrappedDisasmLine(sb, string.Empty, $" ; (symbols truncated: {leGlobalSymbols.Count} total)", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine(";");
                }
            }

            // Two-pass approach:
            //  1) Decode executable objects once and collect cross-object CALL/JMP/Jcc xrefs.
            //  2) Render each object using the global function-start set so that
            //     `func_XXXXXXXX:` labels are emitted for call targets across objects.
            var objByIndex = objects.ToDictionary(o => o.Index);
            var execObjIndices = new HashSet<int>();
            var execObjStartOffset = new Dictionary<int, int>();
            var execObjStartLinear = new Dictionary<int, uint>();
            var execObjEndLinear = new Dictionary<int, uint>();
            var execObjInstructions = new Dictionary<int, List<Instruction>>();
            var execObjInsIndexByAddr = new Dictionary<int, Dictionary<uint, int>>();
            var execObjDecodeMs = new Dictionary<int, long>();
            // Heuristic bookkeeping: addresses of 0x00 bytes immediately after RET/RETF/IRET
            // that we normalize to 0x90 for decoding (to prevent 1-byte misalignment).
            // Rendering uses this to emit `db 0x00` instead of a misleading `nop`.
            var execObjPostRetZeroPadAddrs = new Dictionary<int, HashSet<uint>>();

            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0 || obj.PageCount == 0)
                    continue;

                var isExecutable = (obj.Flags & 0x0004) != 0;
                if (!isExecutable)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes))
                    objBytes = null;
                if (objBytes == null || objBytes.Length == 0)
                    continue;

                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)objBytes.Length);
                if (maxLen <= 0)
                    continue;

                var startOffsetWithinObject = 0;

                // Optional override: start disassembly at an arbitrary LE linear address.
                // This is useful for inspecting code near the entrypoint without rendering the entire object.
                if (leStartLinear.HasValue)
                {
                    var lin = leStartLinear.Value;
                    if (lin >= obj.BaseAddress && lin < obj.BaseAddress + (uint)maxLen)
                        startOffsetWithinObject = (int)(lin - obj.BaseAddress);
                }
                else if (!leFull)
                {
                    if (header.EntryEipObject == (uint)obj.Index && header.EntryEip < (uint)maxLen)
                    {
                        startOffsetWithinObject = (int)header.EntryEip;
                    }
                    else
                    {
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

                var codeLen = maxLen - startOffsetWithinObject;
                // When an explicit start is provided, honor the byte limit even in -LEFULL mode.
                if ((leStartLinear.HasValue || !leFull) && leBytesLimit.HasValue)
                    codeLen = Math.Min(codeLen, leBytesLimit.Value);
                if (codeLen <= 0)
                    continue;

                var code = new byte[codeLen];
                Buffer.BlockCopy(objBytes, startOffsetWithinObject, code, 0, codeLen);

                var startLinear = obj.BaseAddress + (uint)startOffsetWithinObject;
                var endLinear = startLinear + (uint)codeLen;

                // Decode heuristic: normalize short runs of 0x00 padding immediately after a RET.
                // Without this, the linear decoder can start at the 0x00 and consume the first
                // real prologue byte, producing a shifted stream (classic: 00 53 51 => `add [...]`).
                var decodeCode = (byte[])code.Clone();
                var postRetZeroPadAddrs = new HashSet<uint>();
                NormalizePostRetZeroPaddingToNops(decodeCode, startLinear, postRetZeroPadAddrs, maxRun: 32);

                var swDis = Stopwatch.StartNew();
                var dis = new SharpDisasm.Disassembler(decodeCode, ArchitectureMode.x86_32, startLinear, true);
                var instructions = dis.Disassemble().ToList();
                swDis.Stop();

                // Address->instruction index for fast lookups.
                var insIndexByAddr = new Dictionary<uint, int>(instructions.Count);
                for (var ii = 0; ii < instructions.Count; ii++)
                    insIndexByAddr[(uint)instructions[ii].Offset] = ii;

                execObjIndices.Add(obj.Index);
                execObjStartOffset[obj.Index] = startOffsetWithinObject;
                execObjStartLinear[obj.Index] = startLinear;
                execObjEndLinear[obj.Index] = endLinear;
                execObjInstructions[obj.Index] = instructions;
                execObjInsIndexByAddr[obj.Index] = insIndexByAddr;
                execObjDecodeMs[obj.Index] = swDis.ElapsedMilliseconds;
                if (postRetZeroPadAddrs.Count > 0)
                    execObjPostRetZeroPadAddrs[obj.Index] = postRetZeroPadAddrs;
            }

            var globalFunctionStarts = new HashSet<uint>();
            var globalLabelTargets = new HashSet<uint>();

            // Seed from Fixup Table targets (highly reliable cross-references).
            if (globalFixupTargets != null)
            {
                foreach (var t in globalFixupTargets)
                {
                    if (TryMapLinearToObject(objects, t, out var tObjIdx, out var _))
                    {
                        var tObj = objects.FirstOrDefault(o => o.Index == tObjIdx);
                        if (tObj.Index != 0)
                        {
                            if ((tObj.Flags & 0x0004) != 0) // Executable
                                globalFunctionStarts.Add(t);
                            else
                                globalLabelTargets.Add(t);
                        }
                    }
                }
            }

            var globalCallXrefs = new Dictionary<uint, List<uint>>();
            var globalJumpXrefs = new Dictionary<uint, List<uint>>();

            var entryLinearGlobalU64 = ComputeEntryLinear(header, objects);
            if (entryLinearGlobalU64 > 0 && entryLinearGlobalU64 <= uint.MaxValue)
            {
                var entryLinearGlobal = unchecked((uint)entryLinearGlobalU64);
                if (TryMapLinearToObject(objects, entryLinearGlobal, out var entryObjIndex, out var _) &&
                    execObjIndices.Contains(entryObjIndex))
                {
                    globalFunctionStarts.Add(entryLinearGlobal);
                }
            }

            foreach (var obj in objects)
            {
                if (!execObjIndices.Contains(obj.Index))
                    continue;

                var startLinear = execObjStartLinear[obj.Index];
                var endLinear = execObjEndLinear[obj.Index];
                var instructions = execObjInstructions[obj.Index];
                var insIndexByAddr = execObjInsIndexByAddr[obj.Index];

                List<LEFixup> objFixups = null;
                Dictionary<uint, List<LEFixup>> fixupsByInsAddr = null;
                if (leFixups && fixupRecordStream != null && fixupPageOffsets != null)
                {
                    objFixups = ParseFixupsForWindow(header, objects, pageMap, importModules, fileBytes, fixupPageOffsets, fixupRecordStream, null, obj, startLinear, endLinear);
                    if (objFixups != null && objFixups.Count > 0)
                        fixupsByInsAddr = BuildFixupLookupByInstruction(instructions, objFixups.OrderBy(f => f.SiteLinear).ToList());
                }

                // Add obvious prologues as function starts (best-effort sequence scan).
                if (leInsights)
                {
                    for (var i = 0; i + 1 < instructions.Count; i++)
                    {
                        var a = instructions[i]?.ToString() ?? string.Empty;
                        if (!a.Equals("push ebp", StringComparison.OrdinalIgnoreCase))
                            continue;
                        var b = instructions[i + 1]?.ToString() ?? string.Empty;

                        // Some 32-bit DOS4GW/Watcom code uses a prologue like:
                        //   push ebx; push ecx; push edx; push esi; push edi; push ebp; mov ebp, esp
                        // In that case, the true function start is the first push, not the inner "push ebp".
                        static bool IsLeadingPush(string t)
                        {
                            if (string.IsNullOrWhiteSpace(t))
                                return false;
                            t = t.Trim();
                            return t.Equals("push ebx", StringComparison.OrdinalIgnoreCase)
                                || t.Equals("push ecx", StringComparison.OrdinalIgnoreCase)
                                || t.Equals("push edx", StringComparison.OrdinalIgnoreCase)
                                || t.Equals("push esi", StringComparison.OrdinalIgnoreCase)
                                || t.Equals("push edi", StringComparison.OrdinalIgnoreCase);
                        }

                        uint BacktrackPrologStart(int pushEbpIdx)
                        {
                            var j = pushEbpIdx;
                            var limit = Math.Max(0, pushEbpIdx - 8);
                            while (j - 1 >= limit)
                            {
                                var prev = instructions[j - 1]?.ToString() ?? string.Empty;
                                if (!IsLeadingPush(prev))
                                    break;
                                j--;
                            }
                            return (uint)instructions[j].Offset;
                        }

                        if (b.Equals("mov ebp, esp", StringComparison.OrdinalIgnoreCase) || b.StartsWith("sub esp, ", StringComparison.OrdinalIgnoreCase))
                        {
                            var start = BacktrackPrologStart(i);
                            globalFunctionStarts.Add(start);
                        }
                    }
                }

                foreach (var ins in instructions)
                {
                    List<LEFixup> fixupsHere = null;
                    fixupsByInsAddr?.TryGetValue((uint)ins.Offset, out fixupsHere);

                    if (TryGetRelativeBranchTarget(ins, fixupsHere, out var target, out var isCall))
                    {
                        // Map targets across objects; only keep ones that land in executable objects we decoded.
                        if (TryMapLinearToObject(objects, target, out var targetObjIndex, out var _) && execObjIndices.Contains(targetObjIndex))
                        {
                            if (isCall)
                            {
                                globalFunctionStarts.Add(target);
                                if (!globalCallXrefs.TryGetValue(target, out var callers))
                                    globalCallXrefs[target] = callers = new List<uint>();
                                callers.Add((uint)ins.Offset);
                            }
                            else
                            {
                                globalLabelTargets.Add(target);
                                if (!globalJumpXrefs.TryGetValue(target, out var sources))
                                    globalJumpXrefs[target] = sources = new List<uint>();
                                sources.Add((uint)ins.Offset);
                            }
                        }
                    }

                    // Jump-table switches: add indirect case targets to global label/xref sets.
                    if (leInsights)
                    {
                        if (insIndexByAddr.TryGetValue((uint)ins.Offset, out var insIdx))
                        {
                            var wantCases = 16;
                            if (TryParseIndirectJmpTable(ins.Bytes, out var _, out var idxRegProbe, out var scaleProbe))
                            {
                                if (TryInferJumpTableSwitchBound(instructions, insIdx, idxRegProbe, out var inferredCasesProbe, out var _))
                                    wantCases = Math.Min(64, Math.Max(1, inferredCasesProbe));
                            }

                            if (TryGetJumpTableTargets(instructions, insIndexByAddr, insIdx, ins, objects, objBytesByIndex, maxEntries: wantCases, out var _, out var idxReg, out var jtTargets))
                            {
                                var maxCases = 32;
                                var casesToAdd = jtTargets.Count;
                                if (TryInferJumpTableSwitchBound(instructions, insIdx, idxReg, out var inferredCases, out var _))
                                    casesToAdd = Math.Min(casesToAdd, Math.Max(1, inferredCases));
                                casesToAdd = Math.Min(casesToAdd, maxCases);

                                for (var ti = 0; ti < casesToAdd; ti++)
                                {
                                    var t = jtTargets[ti];
                                    if (TryMapLinearToObject(objects, t, out var targetObjIndex, out var _) && execObjIndices.Contains(targetObjIndex))
                                    {
                                        globalLabelTargets.Add(t);
                                        if (!globalJumpXrefs.TryGetValue(t, out var sources))
                                            globalJumpXrefs[t] = sources = new List<uint>();
                                        sources.Add((uint)ins.Offset);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Thunk/vector discovery (best-effort): scan non-executable objects for pointer tables that point at
            // decoded executable instruction starts, and seed those as function entrypoints.
            if (leInsights && objBytesByIndex.Count > 0 && execObjIndices.Count > 0)
            {
                var spans = objects
                    .Select(o => new LeThunkDiscovery.LeObjectSpan(
                        o.Index,
                        o.BaseAddress,
                        o.VirtualSize,
                        (o.Flags & 0x0004) != 0))
                    .ToList();

                bool IsValidExecInsStart(uint target)
                {
                    if (!TryMapLinearToObject(objects, target, out var targetObjIndex, out var _))
                        return false;
                    if (!execObjIndices.Contains(targetObjIndex))
                        return false;
                    return execObjInsIndexByAddr.TryGetValue(targetObjIndex, out var idxByAddr) && idxByAddr.ContainsKey(target);
                }

                var thunkTargets = new HashSet<uint>();
                var tables = LeThunkDiscovery.ScanPointerTablesForTargets(
                    spans,
                    objBytesByIndex,
                    IsValidExecInsStart,
                    thunkTargets,
                    minRunEntries: 6,
                    maxTables: 64,
                    maxEntriesPerTable: 128);

                foreach (var t in thunkTargets)
                    globalFunctionStarts.Add(t);

                if (tables.Count > 0)
                    _logger.Info($"LE: Thunk/vector scan: {tables.Count} tables, {thunkTargets.Count} unique targets (seeded as function starts)");
            }

            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0 || obj.PageCount == 0)
                    continue;

                // Heuristic: treat objects with the EXECUTABLE bit (0x0004) as code.
                // Some toolchains may set different flags; if this is wrong, we still allow disassembling.
                var isExecutable = (obj.Flags & 0x0004) != 0;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var objBytes))
                    objBytes = null;
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
                AppendWrappedDisasmLine(sb, string.Empty, $" ; Object {obj.Index}  Base: 0x{obj.BaseAddress:X8}  Size: 0x{obj.VirtualSize:X}  Flags: 0x{obj.Flags:X8}  Pages: {obj.PageCount}  {(isExecutable ? "CODE" : "DATA?")}", commentColumn: 0, maxWidth: 160);
                AppendWrappedDisasmLine(sb, string.Empty, $" ; Disassembly start: +0x{startOffsetWithinObject:X} (Linear 0x{(obj.BaseAddress + (uint)startOffsetWithinObject):X8})", commentColumn: 0, maxWidth: 160);
                AppendWrappedDisasmLine(sb, string.Empty, " ; LINEAR_ADDR BYTES DISASSEMBLY", commentColumn: 0, maxWidth: 160);
                sb.AppendLine(";-------------------------------------------");

                if (!isExecutable)
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Skipping non-executable object (use -minimal later if you want raw dump support)", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine();
                    continue;
                }

                // If we failed to decode this executable object in the pre-pass, skip rendering.
                if (!execObjIndices.Contains(obj.Index))
                {
                    AppendWrappedDisasmLine(sb, string.Empty, " ; Skipping executable object (no decoded instructions available)", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine();
                    continue;
                }

                _logger.Info($"LE: Disassembling object {obj.Index}/{objects.Count} (base=0x{obj.BaseAddress:X8} pages={obj.PageCount} vsize=0x{obj.VirtualSize:X})");

                var swObjTotal = Stopwatch.StartNew();

                // Use the pre-pass decode window to keep xref/function labeling consistent.
                startOffsetWithinObject = execObjStartOffset[obj.Index];
                var startLinear = execObjStartLinear[obj.Index];
                var endLinear = execObjEndLinear[obj.Index];
                var objDecodeMs = execObjDecodeMs.TryGetValue(obj.Index, out var dms) ? dms : 0;

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
                        objBytes,
                        obj,
                        startLinear,
                        endLinear);
                }

                var instructions = execObjInstructions[obj.Index];
                var insIndexByAddr = execObjInsIndexByAddr[obj.Index];
                _logger.Info($"LE: Object {obj.Index} decoded {instructions.Count} instructions (cached)");

                var jobs = Math.Max(1, leJobs);
                var useParallelInsights = leInsights && jobs > 1;

                var swObjInsights = leInsights ? Stopwatch.StartNew() : null;

                var functionStarts = new HashSet<uint>(
                    globalFunctionStarts.Where(a => a >= startLinear && a < endLinear));
                var labelTargets = new HashSet<uint>(
                    globalLabelTargets.Where(a => a >= startLinear && a < endLinear));
                var callXrefs = new Dictionary<uint, List<uint>>();
                var jumpXrefs = new Dictionary<uint, List<uint>>();

                foreach (var kv in globalCallXrefs)
                {
                    if (kv.Key >= startLinear && kv.Key < endLinear)
                        callXrefs[kv.Key] = kv.Value;
                }
                foreach (var kv in globalJumpXrefs)
                {
                    if (kv.Key >= startLinear && kv.Key < endLinear)
                        jumpXrefs[kv.Key] = kv.Value;
                }

                // Addresses of bytes that were normalized (0x00 -> 0x90) for decoding.
                // Rendering uses this to show the true byte(s) as `db 0x00`.
                execObjPostRetZeroPadAddrs.TryGetValue(obj.Index, out var postRetZeroPadAddrsForObj);

                // Map instruction offset -> fixups that touch bytes within that instruction.
                Dictionary<uint, List<LEFixup>> fixupsByInsAddr = null;
                if (leInsights && objFixups != null && objFixups.Count > 0)
                    fixupsByInsAddr = BuildFixupLookupByInstruction(instructions, objFixups.OrderBy(f => f.SiteLinear).ToList());

                // Function boundary refinement (best-effort): split merged adjacent functions by
                // detecting a classic prolog right after a RET (contiguous code layout).
                if (leInsights && functionStarts.Count > 0)
                {
                    var added = RefineFunctionStartsByPrologAfterRet(instructions, functionStarts);
                    _logger.Info($"LE: Function boundary refinement: +{added} function starts (prolog after ret)");
                }

                // Pre-sorted function list for per-function insight passes.
                // IMPORTANT: filter to decoded instruction addresses to avoid pathological endIdx slicing.
                var sortedStartsForInsights = leInsights && functionStarts != null && functionStarts.Count > 0
                    ? functionStarts.Where(a => insIndexByAddr.ContainsKey(a)).OrderBy(x => x).ToList()
                    : new List<uint>();

                // NOTE: xrefs/targets are collected globally in the pre-pass.

                // Basic-block starts (for insights mode)
                HashSet<uint> blockStarts = null;
                Dictionary<uint, List<uint>> blockPreds = null;
                if (leInsights)
                {
                    BuildBasicBlocks(instructions, startLinear, endLinear, functionStarts, labelTargets, fixupsByInsAddr, out blockStarts, out blockPreds);

                    // Snapshot per-function CFG for exporters (best-effort, derived from relative branches only).
                    if (analysis != null && functionStarts.Count > 0 && blockStarts != null && blockStarts.Count > 0 && blockPreds != null && blockPreds.Count > 0)
                        CaptureCfgSnapshot(analysis, functionStarts, blockStarts, blockPreds);
                }

                // Second pass: render with labels and inline xref hints.
                var sortedFixups = objFixups == null ? null : objFixups.OrderBy(f => f.SiteLinear).ToList();

                HashSet<uint> resourceGetterTargets = null;
                if (leInsights)
                    resourceGetterTargets = DetectResourceGetterTargets(instructions);

                Dictionary<uint, string> globalSymbols = leGlobalSymbols ?? new Dictionary<uint, string>();
                if (leGlobals && sortedFixups != null && sortedFixups.Count > 0)
                {
                    var siteToLinearMap = CollectGlobalSymbols(instructions, sortedFixups, objects);
                    foreach (var kvp in siteToLinearMap)
                    {
                        var siteValue = kvp.Key;
                        var targetLinear = kvp.Value;

                        // Ensure we have a symbol for the target linear address.
                        if (!globalSymbols.TryGetValue(targetLinear, out var symName))
                        {
                            // Use linear-address symbols so the output can define them as numeric constants.
                            symName = $"g_{targetLinear:X8}";
                            globalSymbols[targetLinear] = symName;
                        }
                    }

                    // (We skip printing a per-object EQU table here to avoid incorrectEQU entries mapping site-values to linear names without context).
                }

                // dispatchTableNotes/dispatchTableSymbols are per-run caches (declared above).

                var fixupIdx = 0;

                // Cross references to symbols (insights)
                Dictionary<string, HashSet<uint>> symXrefs = null;
                if (leInsights)
                    symXrefs = new Dictionary<string, HashSet<uint>>(StringComparer.Ordinal);

                // Per-function summaries (insights)
                Dictionary<uint, FunctionSummary> funcSummaries = null;
                if (leInsights)
                {
                    var swSumm = Stopwatch.StartNew();
                    _logger.Info($"LE: Summarizing {functionStarts.Count} functions (insights)...");
                    funcSummaries = SummarizeFunctions(instructions, functionStarts, blockStarts, fixupsByInsAddr, globalSymbols, stringSymbols, objects);
                    HeuristicLabelFunctions(instructions, functionStarts, analysis);
                    _logger.Info($"LE: Function summaries complete in {swSumm.ElapsedMilliseconds} ms");

                    if (analysis != null && funcSummaries != null && funcSummaries.Count > 0)
                    {
                        foreach (var kvp in funcSummaries)
                        {
                            var start = kvp.Key;
                            var fs = kvp.Value;
                            if (fs == null)
                                continue;

                            analysis.Functions[start] = new LeFunctionInfo
                            {
                                Start = start,
                                InstructionCount = fs.InstructionCount,
                                BlockCount = fs.BlockCount,
                                Calls = fs.Calls.OrderBy(x => x).ToList(),
                                Globals = fs.Globals.OrderBy(x => x, StringComparer.Ordinal).ToList(),
                                Strings = fs.Strings.OrderBy(x => x, StringComparer.Ordinal).ToList(),
                            };
                        }
                    }
                }

                // Infer common pointer globals (absolute addresses frequently loaded into a register and used as a base).
                // This is needed early so field summaries can attribute [reg+disp] to ptr_XXXXXXXX bases.
                var inferredPtrSymbols = leInsights ? BuildInferredPointerSymbols(instructions, minBaseUses: 3) : new Dictionary<uint, string>();

                // Per-function field summaries (insights)
                Dictionary<uint, string> funcFieldSummaries = null;
                Dictionary<string, Dictionary<uint, FieldAccessStats>> ptrFieldStatsGlobal = null;
                Dictionary<string, Dictionary<uint, FieldAccessStats>> thisFieldStatsGlobal = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcFieldSummaries = new Dictionary<uint, string>();
                    ptrFieldStatsGlobal = new Dictionary<string, Dictionary<uint, FieldAccessStats>>(StringComparer.Ordinal);
                    thisFieldStatsGlobal = new Dictionary<string, Dictionary<uint, FieldAccessStats>>(StringComparer.Ordinal);
                    var sortedStarts = sortedStartsForInsights;
                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            if ((si % 250) == 0 && si > 0)
                                _logger.Info($"LE: Field summaries... {si}/{sortedStarts.Count}");
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFieldAccessesForFunction(instructions, startIdx, endIdx, out var stats, inferredPtrSymbols);
                            MergeFieldStats(ptrFieldStatsGlobal, stats, b => b.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase));
                            MergeFieldStats(thisFieldStatsGlobal, stats, b => string.Equals(b, "this", StringComparison.OrdinalIgnoreCase));
                            var summary = FormatFieldSummary(stats);
                            if (!string.IsNullOrEmpty(summary))
                                funcFieldSummaries[startAddr] = summary;
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: Field summaries (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var progress = 0;
                        var mergeLock = new object();

                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFieldAccessesForFunction(instructions, startIdx, endIdx, out var stats, inferredPtrSymbols);
                            var summary = FormatFieldSummary(stats);

                            lock (mergeLock)
                            {
                                MergeFieldStats(ptrFieldStatsGlobal, stats, b => b.StartsWith("ptr_", StringComparison.OrdinalIgnoreCase));
                                MergeFieldStats(thisFieldStatsGlobal, stats, b => string.Equals(b, "this", StringComparison.OrdinalIgnoreCase));
                                if (!string.IsNullOrEmpty(summary))
                                    funcFieldSummaries[startAddr] = summary;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 500) == 0)
                                _logger.Info($"LE: Field summaries... {done}/{sortedStarts.Count}");
                        });
                    }
                }

                // Per-function FPU summaries (insights)
                Dictionary<uint, string> funcFpuSummaries = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcFpuSummaries = new Dictionary<uint, string>();
                    var sortedStarts = sortedStartsForInsights;
                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            if ((si % 500) == 0 && si > 0)
                                _logger.Info($"LE: FPU summaries... {si}/{sortedStarts.Count}");
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFpuOpsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFpuSummary(st);
                            if (!string.IsNullOrEmpty(summary))
                                funcFpuSummaries[startAddr] = summary;
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: FPU summaries (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var progress = 0;
                        var dictLock = new object();
                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;
                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFpuOpsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFpuSummary(st);
                            if (!string.IsNullOrEmpty(summary))
                            {
                                lock (dictLock)
                                    funcFpuSummaries[startAddr] = summary;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 1000) == 0)
                                _logger.Info($"LE: FPU summaries... {done}/{sortedStarts.Count}");
                        });
                    }
                }

                // Per-function I/O summaries (insights)
                Dictionary<uint, string> funcIoSummaries = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcIoSummaries = new Dictionary<uint, string>();
                    var sortedStarts = sortedStartsForInsights;
                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            if ((si % 500) == 0 && si > 0)
                                _logger.Info($"LE: IO summaries... {si}/{sortedStarts.Count}");
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectIoPortsForFunction(instructions, startIdx, endIdx, out var ports);
                            var summary = FormatIoPortSummary(ports);
                            if (!string.IsNullOrEmpty(summary))
                                funcIoSummaries[startAddr] = summary;
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: IO summaries (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var progress = 0;
                        var dictLock = new object();
                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;
                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectIoPortsForFunction(instructions, startIdx, endIdx, out var ports);
                            var summary = FormatIoPortSummary(ports);
                            if (!string.IsNullOrEmpty(summary))
                            {
                                lock (dictLock)
                                    funcIoSummaries[startAddr] = summary;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 1000) == 0)
                                _logger.Info($"LE: IO summaries... {done}/{sortedStarts.Count}");
                        });
                    }
                }

                // Per-function flag-bit test summaries (insights)
                Dictionary<uint, string> funcFlagSummaries = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcFlagSummaries = new Dictionary<uint, string>();
                    var sortedStarts = sortedStartsForInsights;
                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            if ((si % 500) == 0 && si > 0)
                                _logger.Info($"LE: Flag summaries... {si}/{sortedStarts.Count}");
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFlagBitTestsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFlagBitSummary(st, null);
                            if (!string.IsNullOrEmpty(summary))
                                funcFlagSummaries[startAddr] = summary;
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: Flag summaries (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var progress = 0;
                        var dictLock = new object();
                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;
                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFlagBitTestsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFlagBitSummary(st, null);
                            if (!string.IsNullOrEmpty(summary))
                            {
                                lock (dictLock)
                                    funcFlagSummaries[startAddr] = summary;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 1000) == 0)
                                _logger.Info($"LE: Flag summaries... {done}/{sortedStarts.Count}");
                        });
                    }
                }

                // Infer common flag variable addresses and emit symbols for them.
                // Keep the threshold fairly high to avoid spamming.
                var inferredFlagSymbols = leInsights ? BuildInferredFlagSymbols(instructions, minTests: 6) : new Dictionary<uint, string>();

                // Per-function out-parameter local aliases (best-effort)
                Dictionary<uint, Dictionary<string, string>> funcOutLocalAliases = null;
                Dictionary<uint, List<string>> funcOutLocalAliasHints = null;
                Dictionary<uint, Dictionary<string, int>> funcLocalBitWidths = null;
                Dictionary<uint, string> funcProtoHints = null;
                Dictionary<uint, string> funcLoopSummaries = null;
                Dictionary<uint, string> funcCSketchHints = null;
                Dictionary<uint, Dictionary<uint, string>> funcLoopHeaderHints = null;
                Dictionary<uint, Dictionary<uint, string>> funcLoopLatchHints = null;
                if (leInsights && functionStarts != null && functionStarts.Count > 0)
                {
                    funcOutLocalAliases = new Dictionary<uint, Dictionary<string, string>>();
                    funcOutLocalAliasHints = new Dictionary<uint, List<string>>();
                    funcLocalBitWidths = new Dictionary<uint, Dictionary<string, int>>();
                    funcProtoHints = new Dictionary<uint, string>();
                    funcLoopSummaries = new Dictionary<uint, string>();
                    funcCSketchHints = new Dictionary<uint, string>();
                    funcLoopHeaderHints = new Dictionary<uint, Dictionary<uint, string>>();
                    funcLoopLatchHints = new Dictionary<uint, Dictionary<uint, string>>();

                    var sortedStarts = sortedStartsForInsights;
                    var sortedBlockStarts = blockStarts != null && blockStarts.Count > 0
                        ? blockStarts.OrderBy(x => x).ToList()
                        : null;

                    // Timing stats for diagnosing slow proto/loop phases.
                    var freq = (double)Stopwatch.Frequency;
                    long protoTicks = 0;
                    long loopTicks = 0;
                    var worst = new List<(uint start, int insCount, long totalTicks, long protoTicks, long loopTicks)>();

                    void RecordWorst(uint start, int insCount, long total, long p, long l)
                    {
                        if (total <= 0)
                            return;
                        worst.Add((start, insCount, total, p, l));
                        if (worst.Count > 6)
                            worst = worst.OrderByDescending(x => x.totalTicks).Take(6).ToList();
                    }

                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            if ((si % 250) == 0 && si > 0)
                            {
                                var protoMs = protoTicks * 1000.0 / freq;
                                var loopMs = loopTicks * 1000.0 / freq;
                                var totMs = (protoTicks + loopTicks) * 1000.0 / freq;

                                var worstText = string.Empty;
                                if (worst.Count > 0)
                                {
                                    var top = worst.OrderByDescending(x => x.totalTicks).Take(3).ToList();
                                    worstText = " ; worst=" + string.Join(", ", top.Select(w =>
                                    {
                                        var ms = w.totalTicks * 1000.0 / freq;
                                        return $"func_{w.start:X8}({w.insCount} ins) {ms:0}ms";
                                    }));
                                }

                                _logger.Info($"LE: Proto/loop/alias hints... {si}/{sortedStarts.Count} (proto {protoMs:0}ms, loops {loopMs:0}ms, total {totMs:0}ms){worstText}");
                                protoTicks = 0;
                                loopTicks = 0;
                                worst.Clear();
                            }

                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            var funcInsCount = Math.Max(0, endIdx - startIdx);

                            var p0 = Stopwatch.GetTimestamp();
                            InferProtoHintsForFunction(instructions, startIdx, endIdx, out var aliases, out var hints, out var bitsByLocal, out var argCount, out var cc, out var retImm);
                            var p1 = Stopwatch.GetTimestamp();
                            var pt = p1 - p0;
                            if (pt > 0)
                                protoTicks += pt;
                            if (aliases != null && aliases.Count > 0)
                                funcOutLocalAliases[startAddr] = aliases;
                            if (hints != null && hints.Count > 0)
                                funcOutLocalAliasHints[startAddr] = hints;

                            if (bitsByLocal != null && bitsByLocal.Count > 0)
                                funcLocalBitWidths[startAddr] = bitsByLocal;

                            if (argCount > 0 || !string.IsNullOrWhiteSpace(cc) || (retImm.HasValue && retImm.Value > 0))
                            {
                                var args = FormatProtoArgs(argCount, maxArgs: 12);
                                var proto = $"PROTO: func_{startAddr:X8}({args})";
                                var ccSuffix = string.IsNullOrWhiteSpace(cc) ? string.Empty : $" ; CC: {cc}";
                                var retSuffix = retImm.HasValue && retImm.Value > 0 ? $" (ret 0x{retImm.Value:X})" : string.Empty;
                                funcProtoHints[startAddr] = proto + ccSuffix + retSuffix;
                            }

                            // Loop/back-edge summaries (best-effort)
                            if (blockStarts != null)
                            {
                                var endAddr = (si + 1 < sortedStarts.Count) ? sortedStarts[si + 1] : uint.MaxValue;
                                var l0 = Stopwatch.GetTimestamp();
                                InferLoopsForFunction(instructions, insIndexByAddr, sortedBlockStarts, startAddr, endAddr, startIdx, endIdx, fixupsByInsAddr, out var loops);
                                var l1 = Stopwatch.GetTimestamp();
                                var lt = l1 - l0;
                                if (lt > 0)
                                    loopTicks += lt;

                                RecordWorst(startAddr, funcInsCount, pt + lt, pt, lt);

                                var loopSum = FormatLoopSummaryForFunction(loops);
                                if (!string.IsNullOrEmpty(loopSum))
                                    funcLoopSummaries[startAddr] = loopSum;

                                if (loops != null && loops.Count > 0)
                                {
                                    var byHdr = new Dictionary<uint, string>();
                                    var byLatch = new Dictionary<uint, string>();
                                    foreach (var l in loops)
                                    {
                                        var hint = FormatLoopHeaderHint(l);
                                        if (!string.IsNullOrWhiteSpace(hint))
                                            byHdr[l.Header] = hint;

                                        if (l.Latches != null && l.Latches.Count > 0)
                                        {
                                            foreach (var la in l.Latches)
                                            {
                                                // Prefer the first-seen header if multiple loops share a latch (rare).
                                                if (!byLatch.ContainsKey(la))
                                                {
                                                    var latchHint = $"LOOPLATCH: hdr=0x{l.Header:X8}";
                                                    if (!string.IsNullOrWhiteSpace(l.InductionVar))
                                                        latchHint += $" iv={l.InductionVar}";
                                                    if (l.Step.HasValue)
                                                        latchHint += $" step={(l.Step.Value >= 0 ? "+" : string.Empty)}{l.Step.Value}";
                                                    if (!string.IsNullOrWhiteSpace(l.Bound))
                                                        latchHint += $" bound={l.Bound}";
                                                    if (!string.IsNullOrWhiteSpace(l.Cond))
                                                        latchHint += $" cond={l.Cond}";
                                                    byLatch[la] = latchHint;
                                                }
                                            }
                                        }
                                    }
                                    if (byHdr.Count > 0)
                                        funcLoopHeaderHints[startAddr] = byHdr;
                                    if (byLatch.Count > 0)
                                        funcLoopLatchHints[startAddr] = byLatch;
                                }

                                // C sketch header (best-effort)
                                var ptrArgs = InferPointerishArgSummaryForFunction(instructions, startIdx, endIdx);
                                var intSum = CollectInterruptSummaryForFunction(instructions, startIdx, endIdx, stringSymbols, stringPreview, objects, objBytesByIndex);
                                FunctionSummary fs = null;
                                string ioSum = null;
                                string protoHint = null;
                                Dictionary<string, int> bw = null;
                                if (funcSummaries != null)
                                    funcSummaries.TryGetValue(startAddr, out fs);
                                if (funcIoSummaries != null)
                                    funcIoSummaries.TryGetValue(startAddr, out ioSum);
                                if (funcProtoHints != null)
                                    funcProtoHints.TryGetValue(startAddr, out protoHint);
                                if (funcLocalBitWidths != null)
                                    funcLocalBitWidths.TryGetValue(startAddr, out bw);
                                var csk = FormatCSketchHeader(startAddr, protoHint, aliases, bw, ptrArgs, fs, ioSum, intSum, loopSum);
                                if (!string.IsNullOrWhiteSpace(csk))
                                    funcCSketchHints[startAddr] = csk;
                            }
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: Proto/loop/alias hints (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var dictLock = new object();
                        var progress = 0;
                        var swProtoLoop = Stopwatch.StartNew();

                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            InferProtoHintsForFunction(instructions, startIdx, endIdx, out var aliases, out var hints, out var bitsByLocal, out var argCount, out var cc, out var retImm);

                            string protoHintOut = null;
                            if (argCount > 0 || !string.IsNullOrWhiteSpace(cc) || (retImm.HasValue && retImm.Value > 0))
                            {
                                var args = FormatProtoArgs(argCount, maxArgs: 12);
                                protoHintOut = $"PROTO: func_{startAddr:X8}({args})";
                                var ccSuffix = string.IsNullOrWhiteSpace(cc) ? string.Empty : $" ; CC: {cc}";
                                var retSuffix = retImm.HasValue && retImm.Value > 0 ? $" (ret 0x{retImm.Value:X})" : string.Empty;
                                protoHintOut += ccSuffix + retSuffix;
                            }

                            string loopSum = null;
                            Dictionary<uint, string> byHdr = null;
                            Dictionary<uint, string> byLatch = null;
                            if (blockStarts != null)
                            {
                                var endAddr = (si + 1 < sortedStarts.Count) ? sortedStarts[si + 1] : uint.MaxValue;
                                InferLoopsForFunction(instructions, insIndexByAddr, sortedBlockStarts, startAddr, endAddr, startIdx, endIdx, fixupsByInsAddr, out var loops);
                                loopSum = FormatLoopSummaryForFunction(loops);

                                if (loops != null && loops.Count > 0)
                                {
                                    byHdr = new Dictionary<uint, string>();
                                    byLatch = new Dictionary<uint, string>();
                                    foreach (var l in loops)
                                    {
                                        var hint = FormatLoopHeaderHint(l);
                                        if (!string.IsNullOrWhiteSpace(hint))
                                            byHdr[l.Header] = hint;

                                        if (l.Latches != null && l.Latches.Count > 0)
                                        {
                                            foreach (var la in l.Latches)
                                            {
                                                if (byLatch.ContainsKey(la))
                                                    continue;
                                                var latchHint = $"LOOPLATCH: hdr=0x{l.Header:X8}";
                                                if (!string.IsNullOrWhiteSpace(l.InductionVar))
                                                    latchHint += $" iv={l.InductionVar}";
                                                if (l.Step.HasValue)
                                                    latchHint += $" step={(l.Step.Value >= 0 ? "+" : string.Empty)}{l.Step.Value}";
                                                if (!string.IsNullOrWhiteSpace(l.Bound))
                                                    latchHint += $" bound={l.Bound}";
                                                if (!string.IsNullOrWhiteSpace(l.Cond))
                                                    latchHint += $" cond={l.Cond}";
                                                byLatch[la] = latchHint;
                                            }
                                        }
                                    }
                                }
                            }

                            string csk = null;
                            if (blockStarts != null)
                            {
                                var ptrArgs = InferPointerishArgSummaryForFunction(instructions, startIdx, endIdx);
                                var intSum = CollectInterruptSummaryForFunction(instructions, startIdx, endIdx, stringSymbols, stringPreview, objects, objBytesByIndex);
                                FunctionSummary fs = null;
                                string ioSum = null;
                                Dictionary<string, int> bw = null;
                                if (funcSummaries != null)
                                    funcSummaries.TryGetValue(startAddr, out fs);
                                if (funcIoSummaries != null)
                                    funcIoSummaries.TryGetValue(startAddr, out ioSum);
                                if (bitsByLocal != null && bitsByLocal.Count > 0)
                                    bw = bitsByLocal;

                                csk = FormatCSketchHeader(startAddr, protoHintOut, aliases, bw, ptrArgs, fs, ioSum, intSum, loopSum);
                            }

                            lock (dictLock)
                            {
                                if (aliases != null && aliases.Count > 0)
                                    funcOutLocalAliases[startAddr] = aliases;
                                if (hints != null && hints.Count > 0)
                                    funcOutLocalAliasHints[startAddr] = hints;
                                if (bitsByLocal != null && bitsByLocal.Count > 0)
                                    funcLocalBitWidths[startAddr] = bitsByLocal;
                                if (!string.IsNullOrWhiteSpace(protoHintOut))
                                    funcProtoHints[startAddr] = protoHintOut;
                                if (!string.IsNullOrWhiteSpace(loopSum))
                                    funcLoopSummaries[startAddr] = loopSum;
                                if (byHdr != null && byHdr.Count > 0)
                                    funcLoopHeaderHints[startAddr] = byHdr;
                                if (byLatch != null && byLatch.Count > 0)
                                    funcLoopLatchHints[startAddr] = byLatch;
                                if (!string.IsNullOrWhiteSpace(csk))
                                    funcCSketchHints[startAddr] = csk;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 500) == 0)
                                _logger.Info($"LE: Proto/loop/alias hints... {done}/{sortedStarts.Count} (elapsed {swProtoLoop.ElapsedMilliseconds} ms)");
                        });

                        swProtoLoop.Stop();
                        _logger.Info($"LE: Proto/loop/alias hints complete in {swProtoLoop.ElapsedMilliseconds} ms");
                    }
                }

                // Re-format per-function flag summaries using the inferred symbols (when available).
                if (leInsights && funcFlagSummaries != null && funcFlagSummaries.Count > 0 && inferredFlagSymbols.Count > 0)
                {
                    var sortedStarts = sortedStartsForInsights;
                    if (!useParallelInsights)
                    {
                        for (var si = 0; si < sortedStarts.Count; si++)
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                continue;

                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFlagBitTestsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFlagBitSummary(st, inferredFlagSymbols);
                            if (!string.IsNullOrEmpty(summary))
                                funcFlagSummaries[startAddr] = summary;
                        }
                    }
                    else
                    {
                        _logger.Info($"LE: Reformatting flag summaries (parallel jobs={jobs})... {sortedStarts.Count} functions");
                        var progress = 0;
                        var dictLock = new object();
                        Parallel.For(0, sortedStarts.Count, new ParallelOptions { MaxDegreeOfParallelism = jobs }, si =>
                        {
                            var startAddr = sortedStarts[si];
                            if (!insIndexByAddr.TryGetValue(startAddr, out var startIdx))
                                return;
                            var endIdx = instructions.Count;
                            if (si + 1 < sortedStarts.Count && insIndexByAddr.TryGetValue(sortedStarts[si + 1], out var nextIdx))
                                endIdx = nextIdx;

                            CollectFlagBitTestsForFunction(instructions, startIdx, endIdx, out var st);
                            var summary = FormatFlagBitSummary(st, inferredFlagSymbols);
                            if (!string.IsNullOrEmpty(summary))
                            {
                                lock (dictLock)
                                    funcFlagSummaries[startAddr] = summary;
                            }

                            var done = Interlocked.Increment(ref progress);
                            if ((done % 1000) == 0)
                                _logger.Info($"LE: Flag reformat... {done}/{sortedStarts.Count}");
                        });
                    }
                }

                if (leInsights && inferredFlagSymbols.Count > 0)
                {
                    sb.AppendLine(";");
                    sb.AppendLine("; Inferred Flag Variables (best-effort, from repeated single-bit tests)");
                    foreach (var kvp in inferredFlagSymbols.OrderBy(k => k.Key).Take(64))
                        sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8} ; bitfield (inferred)");
                    if (inferredFlagSymbols.Count > 64)
                        sb.AppendLine($";   (flag symbol table truncated: {inferredFlagSymbols.Count} entries)");
                    sb.AppendLine(";");
                }

                if (leInsights && inferredPtrSymbols.Count > 0)
                {
                    sb.AppendLine(";");
                    sb.AppendLine("; Inferred Pointer Variables (best-effort, from base+disp access patterns)");
                    foreach (var kvp in inferredPtrSymbols.OrderBy(k => k.Key).Take(64))
                        sb.AppendLine($"{kvp.Value} EQU 0x{kvp.Key:X8} ; ptr (inferred)");
                    if (inferredPtrSymbols.Count > 64)
                        sb.AppendLine($";   (ptr symbol table truncated: {inferredPtrSymbols.Count} entries)");
                    sb.AppendLine(";");
                }

                if (leInsights && ptrFieldStatsGlobal != null && ptrFieldStatsGlobal.Count > 0)
                {
                    var table = FormatPointerStructTable(ptrFieldStatsGlobal);
                    if (!string.IsNullOrWhiteSpace(table))
                        sb.Append(table);
                }

                if (leInsights && thisFieldStatsGlobal != null && thisFieldStatsGlobal.Count > 0)
                {
                    var table = FormatThisStructTable(thisFieldStatsGlobal);
                    if (!string.IsNullOrWhiteSpace(table))
                        sb.Append(table);
                }

                // Live alias tracking for operand rewriting during rendering.
                var liveAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ecx"] = "this"
                };

                // Per-function arg aliasing (best-effort). Keys are like "arg_0".
                var argAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                // Per-function pointer-ish tracking: reg -> (arg_/local_) token.
                var ptrTokenByReg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                // Per-function local aliasing (best-effort). Keys are like "local_1C".
                var localAliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                if (swObjInsights != null)
                {
                    swObjInsights.Stop();
                    _logger.Info($"LE: Object {obj.Index} insights complete in {swObjInsights.ElapsedMilliseconds} ms");
                }

                var renderLimit = leRenderLimit.HasValue ? Math.Max(0, leRenderLimit.Value) : int.MaxValue;

                if (renderLimit == 0)
                {
                    _logger.Info($"LE: Rendering object {obj.Index} skipped (render disabled) ({instructions.Count} instructions)");
                    AppendWrappedDisasmLine(sb, string.Empty, $" ; (Rendering skipped: -lerenderlimit 0) ; decoded {instructions.Count} instructions ; functions {functionStarts.Count}", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine();
                    continue;
                }

                _logger.Info($"LE: Rendering object {obj.Index} ({instructions.Count} instructions)...");

                var swObjRender = Stopwatch.StartNew();

                uint currentFunctionStart = 0;

                ushort? lastDxImm16 = null;
                string lastDxSource = null;
                byte? lastAlImm8 = null;
                ushort? lastAxImm16 = null;

                // Suppress repeating switch/decision-tree hints on every bb_ label inside the same compare chain.
                string lastSwitchSig = null;
                int lastSwitchIdx = int.MinValue;
                var emittedSwitchSigs = new HashSet<string>(StringComparer.Ordinal);

                var maxToRender = Math.Min(instructions.Count, renderLimit);
                for (var insLoopIndex = 0; insLoopIndex < maxToRender; insLoopIndex++)
                {
                    if (leInsights && (insLoopIndex % 50000) == 0 && insLoopIndex > 0)
                        _logger.Info($"LE: Rendering object {obj.Index}... {insLoopIndex}/{instructions.Count} ins");

                    var ins = instructions[insLoopIndex];
                    var addr = (uint)ins.Offset;

                    // Heuristic: if we just saw a RET and the following bytes have no known xrefs,
                    // they're often padding/data (or a non-linear entry) that SharpDisasm will happily decode.
                    // We don't change the decode here, but we add a clear note to avoid “why is this random?” moments.
                    var postRetNoXref = false;
                    if (insLoopIndex > 0)
                    {
                        var prevText = instructions[insLoopIndex - 1]?.ToString() ?? string.Empty;
                        if (prevText.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                        {
                            var hasIncoming = (callXrefs != null && callXrefs.ContainsKey(addr)) || (jumpXrefs != null && jumpXrefs.ContainsKey(addr));
                            var isEntry = (functionStarts != null && functionStarts.Contains(addr)) || (labelTargets != null && labelTargets.Contains(addr));
                            if (!hasIncoming && !isEntry)
                                postRetNoXref = true;
                        }
                    }

                    // Best-effort reset at likely function prologues even when we failed to
                    // identify the start as a call target. This prevents alias state from
                    // leaking across adjacent functions in linear disassembly.
                    if (leInsights && !functionStarts.Contains(addr) && LooksLikeFunctionFrameSetup(instructions, insLoopIndex))
                    {
                        currentFunctionStart = 0;
                        lastSwitchSig = null;
                        lastSwitchIdx = int.MinValue;
                        emittedSwitchSigs.Clear();
                        localAliases.Clear();
                        argAliases.Clear();
                        ptrTokenByReg.Clear();

                        liveAliases.Clear();
                        liveAliases["ecx"] = "this";

                        lastDxImm16 = null;
                        lastDxSource = null;
                        lastAlImm8 = null;
                        lastAxImm16 = null;
                    }

                    if (functionStarts.Contains(addr))
                    {
                        sb.AppendLine();
                        if (analysis != null && analysis.ExportedNames.TryGetValue(addr, out var expName))
                        {
                            sb.AppendLine($"{expName}: ; func_{addr:X8}");
                        }
                        else
                        {
                            sb.AppendLine($"func_{addr:X8}:");
                        }

                        currentFunctionStart = addr;

                        // Reset per-function hint dedup state.
                        lastSwitchSig = null;
                        lastSwitchIdx = int.MinValue;
                        emittedSwitchSigs.Clear();

                        // Reset per-function local aliasing.
                        localAliases.Clear();
                        argAliases.Clear();
                        ptrTokenByReg.Clear();

                        if (leInsights && funcOutLocalAliases != null && funcOutLocalAliases.TryGetValue(addr, out var preAliases) && preAliases != null)
                        {
                            foreach (var kv in preAliases)
                            {
                                var alias = kv.Value;
                                if (leInsights && funcLocalBitWidths != null && funcLocalBitWidths.TryGetValue(addr, out var bw) && bw != null && bw.TryGetValue(kv.Key, out var bits))
                                    alias = UpgradeOutpAliasWithBitWidth(alias, bits);
                                localAliases[kv.Key] = alias;
                            }
                        }

                        // Pointer-ish aliases are updated on-the-fly during rendering.

                        if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; XREF: called from {string.Join(", ", callers.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && resourceGetterTargets != null && resourceGetterTargets.Contains(addr))
                            AppendWrappedDisasmLine(sb, string.Empty, " ; ROLE: res_get(base=edx, id=eax) -> eax (best-effort)", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcProtoHints != null && funcProtoHints.TryGetValue(addr, out var protoHint) && !string.IsNullOrWhiteSpace(protoHint))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {protoHint}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcCSketchHints != null && funcCSketchHints.TryGetValue(addr, out var csk) && !string.IsNullOrWhiteSpace(csk))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {csk}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcSummaries != null && funcSummaries.TryGetValue(addr, out var summary))
                            AppendWrappedDisasmLine(sb, string.Empty, $" {summary.ToComment()}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcOutLocalAliasHints != null && funcOutLocalAliasHints.TryGetValue(addr, out var outHints) && outHints != null)
                        {
                            foreach (var h in outHints.Take(8))
                                AppendWrappedDisasmLine(sb, string.Empty, $" ; {h}", commentColumn: 0, maxWidth: 160);
                        }

                        if (leInsights && funcIoSummaries != null && funcIoSummaries.TryGetValue(addr, out var ioSum))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; IO: {ioSum}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcFlagSummaries != null && funcFlagSummaries.TryGetValue(addr, out var flagSum))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; FLAGS: {flagSum}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && funcFpuSummaries != null && funcFpuSummaries.TryGetValue(addr, out var fpuSum))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; FPU: {fpuSum}", commentColumn: 0, maxWidth: 160);

                        if (leInsights)
                        {
                            var critHint = TryAnnotateCriticalSectionIo(instructions, insLoopIndex);
                            if (!string.IsNullOrEmpty(critHint))
                                AppendWrappedDisasmLine(sb, string.Empty, $" ; {critHint}", commentColumn: 0, maxWidth: 160);
                        }

                        if (leInsights && funcFieldSummaries != null && funcFieldSummaries.TryGetValue(addr, out var fsum))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {fsum}", commentColumn: 0, maxWidth: 160);

                        // Reset aliases at function boundary.
                        liveAliases.Clear();
                        liveAliases["ecx"] = "this";

                        // Reset per-function port tracking to avoid stale DX.
                        lastDxImm16 = null;
                        lastDxSource = null;
                        lastAlImm8 = null;
                        lastAxImm16 = null;
                    }
                    else if (labelTargets.Contains(addr))
                    {
                        sb.AppendLine($"loc_{addr:X8}:");
                        if (jumpXrefs.TryGetValue(addr, out var sources) && sources.Count > 0)
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; XREF: jumped from {string.Join(", ", sources.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && currentFunctionStart != 0 && funcLoopHeaderHints != null && funcLoopHeaderHints.TryGetValue(currentFunctionStart, out var byHdr) && byHdr != null && byHdr.TryGetValue(addr, out var lh) && !string.IsNullOrWhiteSpace(lh))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {lh}", commentColumn: 0, maxWidth: 160);

                        if (leInsights)
                        {
                            var sw = TryAnnotateByteSwitchDecisionTree(instructions, insIndexByAddr, insLoopIndex, stringSymbols, stringPreview, objects, objBytesByIndex, out var swSig, out var inferredLocals, out var aliasHints);
                            if (!string.IsNullOrEmpty(sw) && !string.IsNullOrEmpty(swSig))
                            {
                                if (!(swSig == lastSwitchSig && (insLoopIndex - lastSwitchIdx) <= 64) && !emittedSwitchSigs.Contains(swSig))
                                {
                                    // Merge inferred local aliases (only if not already set).
                                    if (inferredLocals != null && inferredLocals.Count > 0)
                                    {
                                        foreach (var kv in inferredLocals)
                                            if (!localAliases.ContainsKey(kv.Key))
                                                localAliases[kv.Key] = kv.Value;
                                    }

                                    AppendWrappedDisasmLine(sb, string.Empty, $" ; {sw}", commentColumn: 0, maxWidth: 160);

                                    if (aliasHints != null && aliasHints.Count > 0)
                                    {
                                        foreach (var h in aliasHints.Take(8))
                                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {h}", commentColumn: 0, maxWidth: 160);
                                    }
                                    lastSwitchSig = swSig;
                                    lastSwitchIdx = insLoopIndex;
                                    emittedSwitchSigs.Add(swSig);
                                }
                            }
                        }
                    }
                    else if (leInsights && blockStarts != null && blockStarts.Contains(addr))
                    {
                        sb.AppendLine($"bb_{addr:X8}:");
                        if (blockPreds != null && blockPreds.TryGetValue(addr, out var preds) && preds.Count > 0)
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; CFG: preds {string.Join(", ", preds.Distinct().OrderBy(x => x).Select(x => $"0x{x:X8}"))}", commentColumn: 0, maxWidth: 160);

                        if (leInsights && currentFunctionStart != 0 && funcLoopHeaderHints != null && funcLoopHeaderHints.TryGetValue(currentFunctionStart, out var byHdr) && byHdr != null && byHdr.TryGetValue(addr, out var lh) && !string.IsNullOrWhiteSpace(lh))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {lh}", commentColumn: 0, maxWidth: 160);

                        var bbHint = TryAnnotateBasicBlockSummary(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(bbHint))
                            AppendWrappedDisasmLine(sb, string.Empty, $" ; {bbHint}", commentColumn: 0, maxWidth: 160);

                        var sw = TryAnnotateByteSwitchDecisionTree(instructions, insIndexByAddr, insLoopIndex, stringSymbols, stringPreview, objects, objBytesByIndex, out var swSig, out var inferredLocals, out var aliasHints);
                        if (!string.IsNullOrEmpty(sw) && !string.IsNullOrEmpty(swSig))
                        {
                            if (!(swSig == lastSwitchSig && (insLoopIndex - lastSwitchIdx) <= 64) && !emittedSwitchSigs.Contains(swSig))
                            {
                                if (inferredLocals != null && inferredLocals.Count > 0)
                                {
                                    foreach (var kv in inferredLocals)
                                        if (!localAliases.ContainsKey(kv.Key))
                                            localAliases[kv.Key] = kv.Value;
                                }

                                AppendWrappedDisasmLine(sb, string.Empty, $" ; {sw}", commentColumn: 0, maxWidth: 160);

                                if (aliasHints != null && aliasHints.Count > 0)
                                {
                                    foreach (var h in aliasHints.Take(8))
                                        AppendWrappedDisasmLine(sb, string.Empty, $" ; {h}", commentColumn: 0, maxWidth: 160);
                                }
                                lastSwitchSig = swSig;
                                lastSwitchIdx = insLoopIndex;
                                emittedSwitchSigs.Add(swSig);
                            }
                        }
                    }

                    // If this address was normalized for decode, render as data/padding instead of
                    // the synthetic `nop` that only exists in the decode buffer.
                    if (postRetZeroPadAddrsForObj != null && postRetZeroPadAddrsForObj.Contains(addr))
                    {
                        var padPrefix = $"{ins.Offset:X8}h {"00".PadRight(Constants.MAX_INSTRUCTION_LENGTH, ' ')} ";
                        AppendWrappedDisasmLine(sb, padPrefix, "db 0x00 ; PAD: 0x00 after RET (alignment heuristic)", commentColumn: 56, maxWidth: 160);
                        continue;
                    }

                    var bytes = BitConverter.ToString(ins.Bytes).Replace("-", string.Empty);
                    var rawInsText = InsText(ins);
                    var insText = rawInsText;

                    // Update DX immediate tracking before appending any '; ...' annotations.
                    if (TryParseMovDxImmediate(rawInsText, out var dxImm))
                        lastDxImm16 = dxImm;

                    if (leInsights)
                    {
                        insText = RewriteStackFrameOperands(insText);

                        // Update pointer-ish arg/local aliases from the current instruction.
                        UpdatePointerishTokenAliases(insText, ptrTokenByReg, argAliases, localAliases);

                        // Apply any inferred per-function local aliases after stack-frame normalization.
                        insText = RewriteLocalAliasTokens(insText, localAliases);

                        // Apply any inferred per-function arg aliases.
                        insText = RewriteArgAliasTokens(insText, argAliases);

                        // Update aliases based on the *current* instruction before rewriting.
                        UpdatePointerAliases(insText, liveAliases, inferredPtrSymbols);

                        // Rewrite [reg+disp] into [this/argX + field_..] when it looks like a struct access.
                        insText = RewriteFieldOperands(insText, liveAliases);

                        // Rewrite frequently-tested absolute flag variables into symbolic names.
                        if (inferredFlagSymbols != null && inferredFlagSymbols.Count > 0)
                            insText = RewriteFlagSymbols(insText, inferredFlagSymbols);

                        // Rewrite inferred pointer globals into symbols too.
                        if (inferredPtrSymbols != null && inferredPtrSymbols.Count > 0)
                            insText = RewritePointerSymbols(insText, inferredPtrSymbols);
                    }

                    // Update IO tracking on the best-effort rewritten instruction text (so it can capture g_... symbols).
                    UpdateIoTrackingFromInstruction(insText, ref lastDxImm16, ref lastDxSource, ref lastAlImm8, ref lastAxImm16);

                    var haveFixups = sortedFixups != null && sortedFixups.Count > 0;
                    var fixupsHere = haveFixups ? GetFixupsForInstruction(sortedFixups, ins, ref fixupIdx) : new List<LEFixup>(0);

                    if (TryGetRelativeBranchTarget(ins, fixupsHere, out var branchTarget, out var isCall2))
                    {
                        string label;
                        if (isCall2 && analysis != null && analysis.ExportedNames.TryGetValue(branchTarget, out var expName))
                            label = expName;
                        else
                            label = isCall2 ? $"func_{branchTarget:X8}" : $"loc_{branchTarget:X8}";

                        insText += $" ; {(isCall2 ? "call" : "jmp")} {label}";
                    }

                    if (leInsights && currentFunctionStart != 0 && funcLoopLatchHints != null && funcLoopLatchHints.TryGetValue(currentFunctionStart, out var byLatch2) && byLatch2 != null && byLatch2.TryGetValue(addr, out var ll) && !string.IsNullOrWhiteSpace(ll))
                        insText += $" ; {ll}";

                    if (leGlobals && globalSymbols != null && globalSymbols.Count > 0 && fixupsHere.Count > 0)
                        insText = ApplyGlobalSymbolRewrites(ins, insText, fixupsHere, globalSymbols, objects);

                    if (leInsights)
                    {
                        // Fixup-based string rewrites (optional)
                        if (fixupsHere.Count > 0)
                            insText = ApplyStringSymbolRewrites(ins, insText, fixupsHere, stringSymbols, objects);

                        // Replace any matching 0x... literal with known symbol.
                        insText = RewriteKnownAddressLiterals(insText, globalSymbols, stringSymbols, resourceSymbols, objects);

                        // Record xrefs from fixups -> symbols
                        if (symXrefs != null && fixupsHere.Count > 0)
                            RecordSymbolXrefs(symXrefs, (uint)ins.Offset, fixupsHere, globalSymbols, stringSymbols, resourceSymbols, objects);

                        var callHint = TryGetCallArgHint(instructions, insIndexByAddr, ins, fixupsHere, globalSymbols, stringSymbols, stringPreview, objects);
                        if (!string.IsNullOrEmpty(callHint))
                            insText += $" ; CALLHINT: {callHint}";

                        var stackHint = TryAnnotateCallStackCleanup(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(stackHint))
                            insText += $" ; {stackHint}";

                        var dispatchHint = TryAnnotateDispatchTableCall(instructions, insLoopIndex, globalSymbols, objects, objBytesByIndex, dispatchTableNotes, dispatchTableSymbols);
                        if (!string.IsNullOrEmpty(dispatchHint))
                            insText += $" ; {dispatchHint}";

                        var vcall = TryAnnotateVirtualCallDetailed(instructions, insLoopIndex, objects, objBytesByIndex, fixupsByInsAddr, vtblSymbols, vtblSlots);
                        if (!string.IsNullOrEmpty(vcall))
                        {
                            insText += $" ; {vcall}";
                        }
                        else
                        {
                            // Fallback: still mark indirect calls even when we can't resolve the vtable.
                            var virtHint = TryAnnotateVirtualCall(instructions, insLoopIndex);
                            if (!string.IsNullOrEmpty(virtHint))
                                insText += $" ; {virtHint}";
                        }

                        var resStrHint = TryAnnotateResourceStringCall(instructions, insLoopIndex, stringSymbols, stringPreview, objects, objBytesByIndex, resourceSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(resStrHint))
                            insText += $" ; {resStrHint}";

                        var fmtHint = TryAnnotateFormatCall(instructions, insLoopIndex, globalSymbols, stringSymbols, stringPreview, objects, objBytesByIndex, resourceSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(fmtHint))
                            insText += $" ; {fmtHint}";

                        var jt = TryAnnotateJumpTable(instructions, insIndexByAddr, insLoopIndex, ins, fixupsHere, objects, objBytesByIndex, stringSymbols, globalSymbols);
                        if (!string.IsNullOrEmpty(jt))
                            insText += $" ; {jt}";

                        var swBounds = TryAnnotateJumpTableSwitchBounds(instructions, insLoopIndex, ins);
                        if (!string.IsNullOrEmpty(swBounds))
                            insText += $" ; {swBounds}";

                        if (postRetNoXref)
                            insText += " ; NOTE: decoded after RET with no known XREFs (likely data/padding)";

                        // If this instruction references a string symbol (or computes one), inline a short preview.
                        var strInline = TryInlineStringPreview(insText, stringPreview, objects, objBytesByIndex, instructions, insLoopIndex, stringSymbols, resourceGetterTargets);
                        if (!string.IsNullOrEmpty(strInline))
                            insText += $" ; {strInline}";
                    }

                    // Interrupt annotation is useful even without the heavier LE insights pass.
                    var intHint = TryAnnotateInterrupt(instructions, insLoopIndex, stringSymbols, stringPreview, objects, objBytesByIndex);
                    if (!string.IsNullOrEmpty(intHint))
                        insText += $" ; {intHint}";

                    var ioHint = TryAnnotateIoPortAccess(insText, lastDxImm16, lastDxSource, lastAlImm8, lastAxImm16);
                    if (!string.IsNullOrEmpty(ioHint))
                        insText += $" ; {ioHint}";

                    if (leInsights)
                    {
                        var stHint = TryAnnotateStackAlloc(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(stHint))
                            insText += $" ; {stHint}";

                        var zeroLocalsHint = TryAnnotateZeroInitStackLocals(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(zeroLocalsHint))
                            insText += $" ; {zeroLocalsHint}";

                        var pushArgsHint = TryAnnotatePushArgsBeforeIndirectCall(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(pushArgsHint))
                            insText += $" ; {pushArgsHint}";

                        var memsetHint = TryAnnotateRepStosbMemset(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(memsetHint))
                            insText += $" ; {memsetHint}";

                        var memcpyHint = TryAnnotateRepMovsdMemcpy(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(memcpyHint))
                            insText += $" ; {memcpyHint}";

                        var memcpyBytesHint = TryAnnotateMemcpyBytesViaRepMovs(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(memcpyBytesHint))
                            insText += $" ; {memcpyBytesHint}";

                        var remIdxHint = TryAnnotateComputeRemainingIndexIn4(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(remIdxHint))
                            insText += $" ; {remIdxHint}";

                        var qHint = TryAnnotateScale8TableLoad(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(qHint))
                            insText += $" ; {qHint}";

                        var u16Hint = TryAnnotateUnalignedU16LoadViaShr(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(u16Hint))
                            insText += $" ; {u16Hint}";

                        var mod4Hint = TryAnnotateIncAndMod4(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(mod4Hint))
                            insText += $" ; {mod4Hint}";

                        var ptr8Hint = TryAnnotateScale8PtrAdd(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(ptr8Hint))
                            insText += $" ; {ptr8Hint}";

                        var qLoadHint2 = TryAnnotateScale8EntryLoadViaLeaAdd(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(qLoadHint2))
                            insText += $" ; {qLoadHint2}";

                        var movsdHint = TryAnnotateMovsdBlockCopy(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(movsdHint))
                            insText += $" ; {movsdHint}";

                        var eaxStoresHint = TryAnnotateStructStoreStreakAtEax(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(eaxStoresHint))
                            insText += $" ; {eaxStoresHint}";

                        var gptrStoresHint = TryAnnotateGlobalPtrFieldStoreStreak(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(gptrStoresHint))
                            insText += $" ; {gptrStoresHint}";

                        var initLoadedPtrHint = TryAnnotateStructInitDefaultsAtLoadedPtrReg(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(initLoadedPtrHint))
                            insText += $" ; {initLoadedPtrHint}";

                        var initHint3 = TryAnnotateStructInitInterleavedAtEax(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(initHint3))
                            insText += $" ; {initHint3}";

                        var initHint2 = TryAnnotateStructInitDefaultsAtEax(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(initHint2))
                            insText += $" ; {initHint2}";

                        var dlStoreHint = TryAnnotateStructFieldStoreDlAtEaxAfterDefaults(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(dlStoreHint))
                            insText += $" ; {dlStoreHint}";

                        var absStoreHint = TryAnnotateAbsStoreStreak(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(absStoreHint))
                            insText += $" ; {absStoreHint}";

                        var arHint = TryAnnotateArithmeticIdioms(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(arHint))
                            insText += $" ; {arHint}";

                        var tabHint = TryAnnotateByteTableAccumulationUnroll(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(tabHint))
                            insText += $" ; {tabHint}";

                        var advHint = TryAnnotateAddAdc64Advance(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(advHint))
                            insText += $" ; {advHint}";

                        var dataHint = TryAnnotateSuspectDataDecode(instructions, insLoopIndex);
                        if (!string.IsNullOrEmpty(dataHint))
                            insText += $" ; {dataHint}";
                    }

                    var genHint = TryAnnotateGenericInstruction(rawInsText, inferredFlagSymbols);
                    if (!string.IsNullOrEmpty(genHint))
                        insText += $" ; {genHint}";

                    if (leInsights)
                    {
                        var initHint = TryAnnotateInitOnceSentinel(instructions, insLoopIndex, inferredPtrSymbols);
                        if (!string.IsNullOrEmpty(initHint))
                            insText += $" ; {initHint}";
                    }

                    if (haveFixups && fixupsHere.Count > 0)
                    {
                        var fixupText = FormatFixupAnnotation(ins, fixupsHere, objects);
                        if (!string.IsNullOrEmpty(fixupText))
                            insText += $" ; FIXUP: {fixupText}";
                    }

                    var prefix = $"{ins.Offset:X8}h {bytes.PadRight(Constants.MAX_INSTRUCTION_LENGTH, ' ')} ";
                    AppendWrappedDisasmLine(sb, prefix, insText, commentColumn: 56, maxWidth: 160);
                }

                if (maxToRender < instructions.Count)
                {
                    sb.AppendLine();
                    AppendWrappedDisasmLine(sb, string.Empty, $" ; (Render limit reached: rendered {maxToRender}/{instructions.Count} instructions; skipped {instructions.Count - maxToRender})", commentColumn: 0, maxWidth: 160);
                    sb.AppendLine();
                }

                if (leInsights && symXrefs != null && symXrefs.Count > 0)
                {
                    sb.AppendLine(";");
                    sb.AppendLine("; Symbol XREFS (within this object, best-effort)");

                    foreach (var kvp in symXrefs.OrderByDescending(k => k.Value.Count).ThenBy(k => k.Key).Take(64))
                    {
                        var refs = kvp.Value.OrderBy(x => x).Take(12).Select(x => $"0x{x:X8}");
                        sb.AppendLine($";   {kvp.Key} ({kvp.Value.Count}) <- {string.Join(", ", refs)}{(kvp.Value.Count > 12 ? ", ..." : string.Empty)}");
                    }

                    if (symXrefs.Count > 64)
                        sb.AppendLine($";   (xref table truncated: {symXrefs.Count} symbols)");
                }

                swObjRender.Stop();
                swObjTotal.Stop();
                _logger.Info(
                    $"LE: Object {obj.Index} timings: decode={objDecodeMs} ms, insights={(swObjInsights?.ElapsedMilliseconds ?? 0)} ms, render={swObjRender.ElapsedMilliseconds} ms, total={swObjTotal.ElapsedMilliseconds} ms");

                sb.AppendLine();
            }

            if (leInsights && dispatchTableSymbols != null && dispatchTableSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; Dispatch Tables (best-effort: inferred from indexed indirect calls)");

                foreach (var kvp in dispatchTableSymbols.OrderBy(k => k.Key).Take(256))
                {
                    var baseAddr = kvp.Key;
                    var sym = kvp.Value;
                    var note = dispatchTableNotes != null && dispatchTableNotes.TryGetValue(baseAddr, out var n) ? n : string.Empty;
                    if (!string.IsNullOrEmpty(note))
                        sb.AppendLine($"{sym} EQU 0x{baseAddr:X8} ;{note.TrimStart()}");
                    else
                        sb.AppendLine($"{sym} EQU 0x{baseAddr:X8}");
                }

                if (dispatchTableSymbols.Count > 256)
                    sb.AppendLine($"; (dispatch tables truncated: {dispatchTableSymbols.Count} total)");
                sb.AppendLine(";");
            }

            if (leInsights && vtblSymbols != null && vtblSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; VTables (best-effort: inferred from constructor writes + indirect calls)");

                foreach (var kvp in vtblSymbols.OrderBy(k => k.Key).Take(128))
                {
                    var vtblAddr = kvp.Key;
                    var vtblSym = kvp.Value;
                    sb.AppendLine($"; {vtblSym} = 0x{vtblAddr:X8}");

                    if (vtblSlots != null && vtblSlots.TryGetValue(vtblAddr, out var slots) && slots.Count > 0)
                    {
                        foreach (var s in slots.OrderBy(x => x.Key).Take(32))
                        {
                            var slot = s.Key;
                            var target = s.Value;
                            sb.AppendLine($";   slot 0x{slot:X} -> func_{target:X8}");
                        }
                        if (slots.Count > 32)
                            sb.AppendLine($";   (slots truncated: {slots.Count} total)");
                    }
                }

                if (vtblSymbols.Count > 128)
                    sb.AppendLine($"; (vtables truncated: {vtblSymbols.Count} total)");
                sb.AppendLine(";");
            }

            if (leInsights && resourceSymbols != null && resourceSymbols.Count > 0)
            {
                sb.AppendLine(";");
                sb.AppendLine("; Resource Symbols (best-effort: inferred from resource-getter call patterns)");
                foreach (var kvp in resourceSymbols.OrderBy(k => k.Key).Take(1024))
                {
                    var addr2 = kvp.Key;
                    var sym2 = kvp.Value;
                    var prev2 = (stringPreview != null && stringPreview.TryGetValue(addr2, out var p2)) ? p2 : string.Empty;
                    if (!string.IsNullOrEmpty(prev2))
                        sb.AppendLine($"{sym2} EQU 0x{addr2:X8} ; \"{prev2}\"");
                    else
                        sb.AppendLine($"{sym2} EQU 0x{addr2:X8}");
                }
                if (resourceSymbols.Count > 1024)
                    sb.AppendLine($"; (resource symbols truncated: {resourceSymbols.Count} total)");
                sb.AppendLine(";");
            }

            output = sb.ToString();
            _logger.Info($"LE: Disassembly complete in {swTotal.ElapsedMilliseconds} ms");

            if (analysis != null)
                SetLastAnalysis(analysis);
            return true;
        }

        private readonly struct ToolchainMarker
        {
            public readonly int Offset;
            public readonly string Text;

            public ToolchainMarker(int offset, string text)
            {
                Offset = offset;
                Text = text;
            }
        }

        private static List<ToolchainMarker> FindToolchainMarkers(byte[] data, EnumToolchainHint hint, int maxTotalHits)
        {
            var markers = new List<ToolchainMarker>();
            if (data == null || data.Length == 0)
                return markers;

            string[] needles;
            switch (hint)
            {
                case EnumToolchainHint.Borland:
                    needles = new[] { "Borland", "Turbo C", "Turbo Pascal", "TC++", "TURBO" };
                    break;
                case EnumToolchainHint.Watcom:
                    needles = new[] { "WATCOM", "Watcom" };
                    break;
                default:
                    needles = new string[0];
                    break;
            }

            foreach (var needle in needles)
            {
                if (markers.Count >= maxTotalHits)
                    break;

                foreach (var off in FindAsciiOccurrences(data, needle, Math.Max(1, maxTotalHits - markers.Count)))
                {
                    markers.Add(new ToolchainMarker(off, $"\"{needle}\""));
                    if (markers.Count >= maxTotalHits)
                        break;
                }
            }

            return markers;
        }

        private static IEnumerable<int> FindAsciiOccurrences(byte[] data, string needle, int maxHits)
        {
            if (maxHits <= 0)
                yield break;
            if (data == null || data.Length == 0)
                yield break;
            if (string.IsNullOrEmpty(needle))
                yield break;

            var nb = Encoding.ASCII.GetBytes(needle);
            if (nb.Length == 0 || nb.Length > data.Length)
                yield break;

            var hits = 0;
            for (var i = 0; i <= data.Length - nb.Length; i++)
            {
                var ok = true;
                for (var j = 0; j < nb.Length; j++)
                {
                    if (data[i + j] != nb[j])
                    {
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                    continue;

                yield return i;
                hits++;
                if (hits >= maxHits)
                    yield break;

                i += nb.Length - 1;
            }
        }

        private static Dictionary<uint, List<LEFixup>> BuildFixupLookupByInstruction(List<Instruction> instructions, List<LEFixup> sortedFixups)
        {
            if (instructions == null || instructions.Count == 0 || sortedFixups == null || sortedFixups.Count == 0)
                return null;

            static bool Is32BitRelocKind(string kind)
            {
                if (string.IsNullOrWhiteSpace(kind))
                    return false;
                kind = kind.Trim();
                return kind == "imm32" || kind == "imm32?" || kind == "disp32";
            }

            static bool TryNormalizeFixupSiteToFieldStart(Instruction ins, LEFixup f)
            {
                if (ins.Bytes == null || ins.Bytes.Length < 4)
                    return false;

                var begin = (uint)ins.Offset;
                var rawDelta = unchecked((int)(f.SiteLinear - begin));
                if (rawDelta < 0 || rawDelta >= ins.Bytes.Length)
                    return false;

                // Some LE/LX fixup records (notably Watcom/DOS4GW variants) can be slightly off.
                // We've seen:
                //  - fixup sites that point to the *end* of the relocated field (need to shift backwards)
                //  - fixup sites that point at the *start of the instruction* (need to shift forwards to imm/disp)
                // Probe within +/-3 bytes and accept the first location that classifies as a 32-bit reloc field.
                for (var back = 0; back <= 3; back++)
                {
                    var candDelta = rawDelta - back;
                    if (candDelta < 0)
                        continue;
                    if (candDelta + 4 > ins.Bytes.Length)
                        continue;

                    if (!TryClassifyFixupKind(ins, candDelta, out var kind) || !Is32BitRelocKind(kind))
                        continue;

                    f.SiteDelta = (sbyte)Math.Min(sbyte.MaxValue, Math.Max(sbyte.MinValue, candDelta - rawDelta));
                    f.SiteLinear = unchecked(begin + (uint)candDelta);
                    f.Value32 = BitConverter.ToUInt32(ins.Bytes, candDelta);
                    return true;
                }

                for (var fwd = 1; fwd <= 3; fwd++)
                {
                    var candDelta = rawDelta + fwd;
                    if (candDelta < 0)
                        continue;
                    if (candDelta + 4 > ins.Bytes.Length)
                        continue;

                    if (!TryClassifyFixupKind(ins, candDelta, out var kind) || !Is32BitRelocKind(kind))
                        continue;

                    f.SiteDelta = (sbyte)Math.Min(sbyte.MaxValue, Math.Max(sbyte.MinValue, candDelta - rawDelta));
                    f.SiteLinear = unchecked(begin + (uint)candDelta);
                    f.Value32 = BitConverter.ToUInt32(ins.Bytes, candDelta);
                    return true;
                }

                return false;
            }

            // Build a sorted list of instruction start addresses for binary search.
            var starts = new uint[instructions.Count];
            for (var i = 0; i < instructions.Count; i++)
                starts[i] = (uint)instructions[i].Offset;

            var map = new Dictionary<uint, List<LEFixup>>();
            foreach (var f in sortedFixups)
            {
                var site = f.SiteLinear;
                var idx = Array.BinarySearch(starts, site);
                if (idx < 0)
                    idx = ~idx - 1;
                if (idx < 0 || idx >= instructions.Count)
                    continue;

                var ins = instructions[idx];
                var begin = (uint)ins.Offset;
                var len = (uint)(ins.Bytes?.Length ?? 0);
                if (len == 0)
                    continue;

                // Site must fall within the instruction byte range.
                if (site < begin || site >= begin + len)
                    continue;

                // Normalize the site to the start of the relocated field when possible.
                // This improves operand rewriting (globals/strings) and avoids spurious replacements.
                TryNormalizeFixupSiteToFieldStart(ins, f);

                if (!map.TryGetValue(begin, out var list))
                    map[begin] = list = new List<LEFixup>();
                list.Add(f);
            }

            return map;
        }
    }
}
