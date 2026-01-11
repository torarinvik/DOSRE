using System;
using System.Collections.Generic;
using System.Linq;
using DOSRE.Dasm;

namespace DOSRE.Analysis
{
    public static class LeExports
    {
        public sealed class LeCallGraphFunction
        {
            public string addr { get; set; }
            public string name { get; set; }
            public int ins { get; set; }
            public int blocks { get; set; }
            public string[] calls { get; set; }
            public string[] globals { get; set; }
            public string[] strings { get; set; }
        }

        public sealed class LeCallGraphTopEntry
        {
            public string addr { get; set; }
            public string name { get; set; }
            public int count { get; set; }
        }

        public sealed class LeCallGraphExport
        {
            public string input { get; set; }
            public string entry { get; set; }
            public string entryName { get; set; }
            public LeCallGraphFunction[] functions { get; set; }

            // Optional summary fields.
            public string[] roots { get; set; }
            public string[] orphans { get; set; }
            public LeCallGraphTopEntry[] topFanIn { get; set; }
            public LeCallGraphTopEntry[] topFanOut { get; set; }
            public string[][] stronglyConnectedComponents { get; set; }
        }

        public sealed class LeReportExport
        {
            public string input { get; set; }
            public string entry { get; set; }
            public string entryName { get; set; }

            public int functionCount { get; set; }

            public int? cfgFunctionCount { get; set; }
            public int? totalInstructionCount { get; set; }
            public int? totalBasicBlocks { get; set; }
            public int? cfgEdgeCount { get; set; }
            public int? callEdgeCount { get; set; }
            public int? globalCount { get; set; }
            public int? stringCount { get; set; }
        }

        public sealed class LeFixupTableFixup
        {
            public string site { get; set; }
            public string source { get; set; }
            public int delta { get; set; }
            public int logicalPage { get; set; }
            public int physicalPage { get; set; }
            public string type { get; set; }
            public string flags { get; set; }
            public int recordStreamOffset { get; set; }
            public int stride { get; set; }

            public string siteValue32 { get; set; }
            public string siteValue16 { get; set; }

            public string targetKind { get; set; }
            public int? targetObject { get; set; }
            public string targetOffset { get; set; }
            public string targetLinear { get; set; }
            public int? addend32 { get; set; }

            public int? importModuleIndex { get; set; }
            public string importModule { get; set; }
            public string importProcNameOffset { get; set; }
            public string importProc { get; set; }
        }

        public sealed class LeFixupTableChain
        {
            public string targetKind { get; set; }
            public int? targetObject { get; set; }
            public string targetOffset { get; set; }
            public string targetLinear { get; set; }
            public int? importModuleIndex { get; set; }
            public string importProcNameOffset { get; set; }
            public int count { get; set; }
        }

        public sealed class LeFixupTableObject
        {
            public int index { get; set; }
            public string baseAddress { get; set; }
            public string virtualSize { get; set; }
            public string flags { get; set; }
            public int pageMapIndex { get; set; }
            public int pageCount { get; set; }
        }

        public sealed class LeFixupTableExport
        {
            public string input { get; set; }
            public string entry { get; set; }
            public string entryName { get; set; }
            public string pageSize { get; set; }
            public int pages { get; set; }

            public LeFixupTableObject[] objects { get; set; }
            public string[] importModules { get; set; }

            public int fixupCount { get; set; }
            public LeFixupTableFixup[] fixups { get; set; }
            public LeFixupTableChain[] chains { get; set; }
        }

        private static string Hex(uint a2) => $"0x{a2:X8}";
        private static string HexU16(ushort v) => $"0x{v:X4}";
        private static string HexU32(uint v) => $"0x{v:X8}";
        private static string HexU32Short(uint v) => $"0x{v:X}";
        private static string FuncName(uint a2) => $"func_{a2:X8}";

        private static List<List<uint>> ComputeSccs(Dictionary<uint, HashSet<uint>> graph, List<uint> nodes)
        {
            // Tarjan SCC (deterministic order by sorted nodes + sorted successors).
            var index = 0;
            var stack = new Stack<uint>();
            var onStack = new HashSet<uint>();
            var indices = new Dictionary<uint, int>();
            var lowlinks = new Dictionary<uint, int>();
            var result = new List<List<uint>>();

            void StrongConnect(uint v)
            {
                indices[v] = index;
                lowlinks[v] = index;
                index++;
                stack.Push(v);
                onStack.Add(v);

                if (graph.TryGetValue(v, out var succs) && succs != null && succs.Count > 0)
                {
                    foreach (var w in succs.OrderBy(x => x))
                    {
                        if (!indices.ContainsKey(w))
                        {
                            StrongConnect(w);
                            lowlinks[v] = Math.Min(lowlinks[v], lowlinks[w]);
                        }
                        else if (onStack.Contains(w))
                        {
                            lowlinks[v] = Math.Min(lowlinks[v], indices[w]);
                        }
                    }
                }

                if (lowlinks[v] == indices[v])
                {
                    var comp = new List<uint>();
                    while (stack.Count > 0)
                    {
                        var w = stack.Pop();
                        onStack.Remove(w);
                        comp.Add(w);
                        if (w == v)
                            break;
                    }
                    comp.Sort();
                    result.Add(comp);
                }
            }

            foreach (var v in nodes)
            {
                if (!indices.ContainsKey(v))
                    StrongConnect(v);
            }

            // Sort components deterministically by (size desc, first addr asc)
            result = result
                .OrderByDescending(c => c.Count)
                .ThenBy(c => c.Count > 0 ? c[0] : 0)
                .ToList();

            return result;
        }

        public static LeCallGraphExport BuildCallGraphExport(LEDisassembler.LeAnalysis analysis)
        {
            if (analysis == null)
                throw new ArgumentNullException(nameof(analysis));

            var functions = (analysis.Functions ?? new Dictionary<uint, LEDisassembler.LeFunctionInfo>())
                .Values
                .OrderBy(f => f.Start)
                .Select(f => new LeCallGraphFunction
                {
                    addr = Hex(f.Start),
                    name = FuncName(f.Start),
                    ins = f.InstructionCount,
                    blocks = f.BlockCount,
                    calls = (f.Calls ?? new List<uint>()).OrderBy(x => x).Select(Hex).ToArray(),
                    globals = (f.Globals ?? new List<string>()).ToArray(),
                    strings = (f.Strings ?? new List<string>()).ToArray(),
                })
                .ToArray();

            // Summary fields (best-effort, internal edges only).
            var nodes = (analysis.Functions ?? new Dictionary<uint, LEDisassembler.LeFunctionInfo>()).Keys.OrderBy(x => x).ToList();
            var nodeSet = new HashSet<uint>(nodes);

            var outEdges = new Dictionary<uint, HashSet<uint>>();
            var inDegree = nodes.ToDictionary(x => x, _ => 0);
            var outDegree = nodes.ToDictionary(x => x, _ => 0);

            foreach (var fn in (analysis.Functions ?? new Dictionary<uint, LEDisassembler.LeFunctionInfo>()).Values)
            {
                if (fn == null)
                    continue;

                var src = fn.Start;
                if (!nodeSet.Contains(src))
                    continue;

                if (!outEdges.TryGetValue(src, out var set))
                    outEdges[src] = set = new HashSet<uint>();

                if (fn.Calls != null)
                {
                    foreach (var callee in fn.Calls)
                    {
                        if (!nodeSet.Contains(callee))
                            continue;

                        if (set.Add(callee))
                            inDegree[callee] = inDegree[callee] + 1;
                    }
                }

                outDegree[src] = set.Count;
            }

            var roots = nodes.Where(n => inDegree[n] == 0).Select(Hex).ToArray();
            var orphans = nodes.Where(n => inDegree[n] == 0 && outDegree[n] == 0).Select(Hex).ToArray();

            var topFanIn = inDegree
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key)
                .Take(20)
                .Where(kv => kv.Value > 0)
                .Select(kv => new LeCallGraphTopEntry { addr = Hex(kv.Key), name = FuncName(kv.Key), count = kv.Value })
                .ToArray();

            var topFanOut = outDegree
                .OrderByDescending(kv => kv.Value)
                .ThenBy(kv => kv.Key)
                .Take(20)
                .Where(kv => kv.Value > 0)
                .Select(kv => new LeCallGraphTopEntry { addr = Hex(kv.Key), name = FuncName(kv.Key), count = kv.Value })
                .ToArray();

            var sccAll = ComputeSccs(outEdges, nodes);
            bool HasSelfLoop(uint n) => outEdges.TryGetValue(n, out var es) && es != null && es.Contains(n);
            var sccs = sccAll
                .Where(c => c.Count > 1 || (c.Count == 1 && HasSelfLoop(c[0])))
                .Select(c => c.Select(Hex).ToArray())
                .ToArray();

            return new LeCallGraphExport
            {
                input = analysis.InputFile,
                entry = Hex(analysis.EntryLinear),
                entryName = FuncName(analysis.EntryLinear),
                functions = functions,
                roots = roots.Length > 0 ? roots : null,
                orphans = orphans.Length > 0 ? orphans : null,
                topFanIn = topFanIn.Length > 0 ? topFanIn : null,
                topFanOut = topFanOut.Length > 0 ? topFanOut : null,
                stronglyConnectedComponents = sccs.Length > 0 ? sccs : null,
            };
        }

        public static LeReportExport BuildReportExport(LEDisassembler.LeAnalysis analysis)
        {
            if (analysis == null)
                throw new ArgumentNullException(nameof(analysis));

            var functions = analysis.Functions ?? new Dictionary<uint, LEDisassembler.LeFunctionInfo>();
            var cfgByFunction = analysis.CfgByFunction ?? new Dictionary<uint, LEDisassembler.LeFunctionCfg>();

            var functionCount = functions.Count;
            var cfgFunctionCount = cfgByFunction.Count;
            var totalInstructionCount = functions.Values.Sum(f => f?.InstructionCount ?? 0);

            var callEdgeCount = 0;
            var globals = new HashSet<string>(StringComparer.Ordinal);
            var strings = new HashSet<string>(StringComparer.Ordinal);
            foreach (var fn in functions.Values)
            {
                if (fn == null)
                    continue;

                if (fn.Calls != null && fn.Calls.Count > 0)
                    callEdgeCount += fn.Calls.Distinct().Count();

                if (fn.Globals != null)
                {
                    foreach (var g in fn.Globals)
                        if (!string.IsNullOrWhiteSpace(g))
                            globals.Add(g);
                }

                if (fn.Strings != null)
                {
                    foreach (var s in fn.Strings)
                        if (!string.IsNullOrWhiteSpace(s))
                            strings.Add(s);
                }
            }

            var totalBasicBlocks = 0;
            var cfgEdgeCount = 0;
            foreach (var cfg in cfgByFunction.Values)
            {
                if (cfg?.Blocks == null || cfg.Blocks.Count == 0)
                    continue;
                totalBasicBlocks += cfg.Blocks.Count;
                foreach (var b in cfg.Blocks.Values)
                {
                    if (b?.Successors != null)
                        cfgEdgeCount += b.Successors.Count;
                }
            }

            return new LeReportExport
            {
                input = analysis.InputFile,
                entry = Hex(analysis.EntryLinear),
                entryName = FuncName(analysis.EntryLinear),
                functionCount = functionCount,
                cfgFunctionCount = cfgFunctionCount > 0 ? (int?)cfgFunctionCount : null,
                totalInstructionCount = totalInstructionCount > 0 ? (int?)totalInstructionCount : null,
                totalBasicBlocks = totalBasicBlocks > 0 ? (int?)totalBasicBlocks : null,
                cfgEdgeCount = cfgEdgeCount > 0 ? (int?)cfgEdgeCount : null,
                callEdgeCount = callEdgeCount > 0 ? (int?)callEdgeCount : null,
                globalCount = globals.Count > 0 ? (int?)globals.Count : null,
                stringCount = strings.Count > 0 ? (int?)strings.Count : null,
            };
        }

        public static LeFixupTableExport BuildFixupTableExport(LEDisassembler.LeFixupTableInfo table)
        {
            if (table == null)
                throw new ArgumentNullException(nameof(table));

            var objects = (table.objects ?? Array.Empty<LEDisassembler.LeObjectInfo>())
                .OrderBy(o => o.index)
                .Select(o => new LeFixupTableObject
                {
                    index = o.index,
                    baseAddress = HexU32(o.baseAddress),
                    virtualSize = HexU32Short(o.virtualSize),
                    flags = HexU32(o.flags),
                    pageMapIndex = (int)o.pageMapIndex,
                    pageCount = (int)o.pageCount
                })
                .ToArray();

            var fixups = (table.fixups ?? Array.Empty<LEDisassembler.LeFixupRecordInfo>())
                .OrderBy(f => f.siteLinear)
                .ThenBy(f => f.recordStreamOffset)
                .Select(f => new LeFixupTableFixup
                {
                    site = HexU32(f.siteLinear),
                    source = HexU32(f.sourceLinear),
                    delta = f.siteDelta,
                    logicalPage = (int)f.logicalPageNumber,
                    physicalPage = (int)f.physicalPageNumber,
                    type = $"0x{f.type:X2}",
                    flags = $"0x{f.flags:X2}",
                    recordStreamOffset = f.recordStreamOffset,
                    stride = f.stride,
                    siteValue32 = f.siteValue32.HasValue ? HexU32(f.siteValue32.Value) : null,
                    siteValue16 = f.siteValue16.HasValue ? HexU16(f.siteValue16.Value) : null,
                    targetKind = string.IsNullOrWhiteSpace(f.targetKind) ? null : f.targetKind,
                    targetObject = f.targetObject,
                    targetOffset = f.targetOffset.HasValue ? HexU32Short(f.targetOffset.Value) : null,
                    targetLinear = f.targetLinear.HasValue ? HexU32(f.targetLinear.Value) : null,
                    addend32 = f.addend32,
                    importModuleIndex = f.importModuleIndex.HasValue ? (int?)f.importModuleIndex.Value : null,
                    importModule = string.IsNullOrWhiteSpace(f.importModule) ? null : f.importModule,
                    importProcNameOffset = f.importProcNameOffset.HasValue ? HexU32Short(f.importProcNameOffset.Value) : null,
                    importProc = string.IsNullOrWhiteSpace(f.importProc) ? null : f.importProc,
                })
                .ToArray();

            var chains = (table.chains ?? Array.Empty<LEDisassembler.LeFixupChainInfo>())
                .Select(c => new LeFixupTableChain
                {
                    targetKind = c.targetKind,
                    targetObject = c.targetObject,
                    targetOffset = c.targetOffset.HasValue ? HexU32Short(c.targetOffset.Value) : null,
                    targetLinear = c.targetLinear.HasValue ? HexU32(c.targetLinear.Value) : null,
                    importModuleIndex = c.importModuleIndex.HasValue ? (int?)c.importModuleIndex.Value : null,
                    importProcNameOffset = c.importProcNameOffset.HasValue ? HexU32Short(c.importProcNameOffset.Value) : null,
                    count = c.count
                })
                .ToArray();

            return new LeFixupTableExport
            {
                input = table.inputFile,
                entry = HexU32(table.entryLinear),
                entryName = FuncName(table.entryLinear),
                pageSize = HexU32Short(table.pageSize),
                pages = (int)table.numberOfPages,
                objects = objects.Length > 0 ? objects : null,
                importModules = table.importModules != null && table.importModules.Length > 0 ? table.importModules : null,
                fixupCount = fixups.Length,
                fixups = fixups.Length > 0 ? fixups : null,
                chains = chains.Length > 0 ? chains : null,
            };
        }
    }
}
