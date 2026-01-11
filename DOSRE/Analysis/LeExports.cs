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

        private static string Hex(uint a2) => $"0x{a2:X8}";
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
    }
}
