using System.Collections.Generic;
using System.Linq;
using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeExportsTests
    {
        private static LEDisassembler.LeAnalysis MakeTinyAnalysis()
        {
            // Graph:
            //   A -> B, C
            //   B -> C
            //   C -> (none)
            //   D -> D (self-loop)
            //   E isolated orphan
            // SCCs: [D]
            var a = 0x1000u;
            var b = 0x2000u;
            var c = 0x3000u;
            var d = 0x4000u;
            var e = 0x5000u;

            var analysis = new LEDisassembler.LeAnalysis
            {
                InputFile = "tiny.exe",
                EntryLinear = a,
            };

            analysis.Functions[a] = new LEDisassembler.LeFunctionInfo { Start = a, InstructionCount = 10, BlockCount = 2, Calls = new List<uint> { b, c } };
            analysis.Functions[b] = new LEDisassembler.LeFunctionInfo { Start = b, InstructionCount = 5, BlockCount = 1, Calls = new List<uint> { c } };
            analysis.Functions[c] = new LEDisassembler.LeFunctionInfo { Start = c, InstructionCount = 1, BlockCount = 1, Calls = new List<uint>() };
            analysis.Functions[d] = new LEDisassembler.LeFunctionInfo { Start = d, InstructionCount = 2, BlockCount = 1, Calls = new List<uint> { d } };
            analysis.Functions[e] = new LEDisassembler.LeFunctionInfo { Start = e, InstructionCount = 3, BlockCount = 1, Calls = new List<uint>() };

            // Minimal CFG snapshot for report counts.
            foreach (var fn in analysis.Functions.Keys)
            {
                var cfg = new LEDisassembler.LeFunctionCfg { FunctionStart = fn };
                cfg.Blocks[fn] = new LEDisassembler.LeBasicBlockInfo { Start = fn, Successors = new List<uint>() };
                analysis.CfgByFunction[fn] = cfg;
            }

            // Add a couple of CFG edges for deterministic edge count.
            analysis.CfgByFunction[a].Blocks[a].Successors.Add(b);
            analysis.CfgByFunction[a].Blocks[a].Successors.Add(c);
            analysis.CfgByFunction[b].Blocks[b].Successors.Add(c);

            return analysis;
        }

        [Fact]
        public void CallGraphExport_IncludesExpectedSummaryFields()
        {
            var analysis = MakeTinyAnalysis();
            var export = LeExports.BuildCallGraphExport(analysis);

            Assert.Equal("tiny.exe", export.input);
            Assert.Equal("0x00001000", export.entry);
            Assert.Equal("func_00001000", export.entryName);
            Assert.Equal(5, export.functions.Length);

            // Roots: A, E (B,C have incoming; D has a self-loop which counts as incoming)
            Assert.NotNull(export.roots);
            Assert.Equal(new[] { "0x00001000", "0x00005000" }, export.roots);

            // Orphans: only E
            Assert.NotNull(export.orphans);
            Assert.Equal(new[] { "0x00005000" }, export.orphans);

            // SCCs: should include [D] because self-loop is treated as interesting.
            Assert.NotNull(export.stronglyConnectedComponents);
            Assert.Contains(export.stronglyConnectedComponents, c => c.SequenceEqual(new[] { "0x00004000" }));

            // Fan-in: C should have 2 unique callers (A,B)
            Assert.NotNull(export.topFanIn);
            var cEntry = export.topFanIn.FirstOrDefault(x => x.addr == "0x00003000");
            Assert.NotNull(cEntry);
            Assert.Equal(2, cEntry!.count);

            // Fan-out: A should have 2 unique callees
            Assert.NotNull(export.topFanOut);
            var aEntry = export.topFanOut.FirstOrDefault(x => x.addr == "0x00001000");
            Assert.NotNull(aEntry);
            Assert.Equal(2, aEntry!.count);
        }

        [Fact]
        public void ReportExport_ComputesDeterministicCounts()
        {
            var analysis = MakeTinyAnalysis();
            var report = LeExports.BuildReportExport(analysis);

            Assert.Equal("tiny.exe", report.input);
            Assert.Equal("0x00001000", report.entry);
            Assert.Equal("func_00001000", report.entryName);

            Assert.Equal(5, report.functionCount);
            Assert.Equal(5, report.cfgFunctionCount);

            // Instructions: 10+5+1+2+3=21
            Assert.Equal(21, report.totalInstructionCount);

            // One block per function.
            Assert.Equal(5, report.totalBasicBlocks);

            // CFG edges: A->B, A->C, B->C => 3
            Assert.Equal(3, report.cfgEdgeCount);

            // Call edges: A has 2, B has 1, D has 1 (self), others 0 => 4
            Assert.Equal(4, report.callEdgeCount);

            // Optional header/import/fixup fields should not be set without a table.
            Assert.Null(report.detectedFormat);
            Assert.Null(report.pageSize);
            Assert.Null(report.pages);
            Assert.Null(report.objectCount);
            Assert.Null(report.objects);
            Assert.Null(report.importModuleCount);
            Assert.Null(report.importModules);
            Assert.Null(report.fixupCount);
            Assert.Null(report.fixupChainCount);
            Assert.Null(report.fixupTargetKindCounts);
            Assert.Null(report.fixupTableError);
        }

        [Fact]
        public void ReportExport_IncludesHeaderImportAndFixupSummary_WhenTableProvided()
        {
            var analysis = MakeTinyAnalysis();

            var table = new LEDisassembler.LeFixupTableInfo
            {
                inputFile = "tiny.exe",
                entryLinear = 0x1000u,
                pageSize = 0x1000u,
                numberOfPages = 3,
                objects = new[]
                {
                    new LEDisassembler.LeObjectInfo { index = 1, baseAddress = 0x00010000u, virtualSize = 0x2000u, flags = 0x00000005u, pageMapIndex = 1u, pageCount = 2u },
                    new LEDisassembler.LeObjectInfo { index = 2, baseAddress = 0x00020000u, virtualSize = 0x1000u, flags = 0x00000001u, pageMapIndex = 3u, pageCount = 1u },
                },
                importModules = new[] { "DOSCALLS", "DPMI" },
                fixups = new[]
                {
                    new LEDisassembler.LeFixupRecordInfo { siteLinear = 0x00010010u, targetKind = "import" },
                    new LEDisassembler.LeFixupRecordInfo { siteLinear = 0x00010020u, targetKind = "internal" },
                    new LEDisassembler.LeFixupRecordInfo { siteLinear = 0x00010030u, targetKind = "import" },
                    new LEDisassembler.LeFixupRecordInfo { siteLinear = 0x00010040u, targetKind = null },
                },
                chains = new[]
                {
                    new LEDisassembler.LeFixupChainInfo { targetKind = "import", count = 2 },
                }
            };

            var report = LeExports.BuildReportExport(analysis, table, detectedFormat: "LE");

            Assert.Equal("LE", report.detectedFormat);
            Assert.Equal("0x1000", report.pageSize);
            Assert.Equal(3, report.pages);

            Assert.Equal(2, report.objectCount);
            Assert.NotNull(report.objects);
            Assert.Equal(2, report.objects!.Length);
            Assert.Equal(1, report.objects[0].index);
            Assert.Equal("0x00010000", report.objects[0].baseAddress);
            Assert.Equal("0x2000", report.objects[0].virtualSize);

            Assert.Equal(2, report.importModuleCount);
            Assert.Equal(new[] { "DOSCALLS", "DPMI" }, report.importModules);

            Assert.Equal(4, report.fixupCount);
            Assert.Equal(1, report.fixupChainCount);

            Assert.NotNull(report.fixupTargetKindCounts);
            Assert.Equal(3, report.fixupTargetKindCounts!.Count);
            Assert.Equal(1, report.fixupTargetKindCounts["internal"]);
            Assert.Equal(2, report.fixupTargetKindCounts["import"]);
            Assert.Equal(1, report.fixupTargetKindCounts["unknown"]);
        }

        [Fact]
        public void CallGraphExport_SccsAreIncludedAndSortedDeterministically()
        {
            // Two SCCs:
            //   SCC1 size=3: A<->B<->C<->A
            //   SCC2 size=2: D<->E
            // plus one leaf F
            var a = 0x1000u;
            var b = 0x2000u;
            var c = 0x3000u;
            var d = 0x4000u;
            var e = 0x5000u;
            var f = 0x6000u;

            var analysis = new LEDisassembler.LeAnalysis { InputFile = "scc.exe", EntryLinear = a };
            analysis.Functions[a] = new LEDisassembler.LeFunctionInfo { Start = a, Calls = new List<uint> { b } };
            analysis.Functions[b] = new LEDisassembler.LeFunctionInfo { Start = b, Calls = new List<uint> { c } };
            analysis.Functions[c] = new LEDisassembler.LeFunctionInfo { Start = c, Calls = new List<uint> { a } };
            analysis.Functions[d] = new LEDisassembler.LeFunctionInfo { Start = d, Calls = new List<uint> { e } };
            analysis.Functions[e] = new LEDisassembler.LeFunctionInfo { Start = e, Calls = new List<uint> { d } };
            analysis.Functions[f] = new LEDisassembler.LeFunctionInfo { Start = f, Calls = new List<uint>() };

            var export = LeExports.BuildCallGraphExport(analysis);
            Assert.NotNull(export.stronglyConnectedComponents);

            // Sorted by size desc then lowest address asc.
            Assert.True(export.stronglyConnectedComponents!.Length >= 2);
            Assert.Equal(new[] { "0x00001000", "0x00002000", "0x00003000" }, export.stronglyConnectedComponents[0]);
            Assert.Equal(new[] { "0x00004000", "0x00005000" }, export.stronglyConnectedComponents[1]);
        }

        [Fact]
        public void CallGraphExport_DisconnectedSubgraphsAndTiesAreDeterministic()
        {
            // Disconnected components:
            //   Component1: A -> C
            //   Component2: B -> C
            //   Component3: D orphan
            // Roots should be A,B,D (C has in-degree 2).
            // Fan-out ties: A and B both out-degree 1; should order by address.
            // Fan-in: C has in-degree 2.
            var a = 0x1000u;
            var b = 0x1100u;
            var c = 0x2000u;
            var d = 0x3000u;

            var analysis = new LEDisassembler.LeAnalysis { InputFile = "disc.exe", EntryLinear = a };
            analysis.Functions[a] = new LEDisassembler.LeFunctionInfo { Start = a, Calls = new List<uint> { c } };
            analysis.Functions[b] = new LEDisassembler.LeFunctionInfo { Start = b, Calls = new List<uint> { c } };
            analysis.Functions[c] = new LEDisassembler.LeFunctionInfo { Start = c, Calls = new List<uint>() };
            analysis.Functions[d] = new LEDisassembler.LeFunctionInfo { Start = d, Calls = new List<uint>() };

            var export = LeExports.BuildCallGraphExport(analysis);

            Assert.NotNull(export.roots);
            Assert.Equal(new[] { "0x00001000", "0x00001100", "0x00003000" }, export.roots);

            Assert.NotNull(export.orphans);
            Assert.Equal(new[] { "0x00003000" }, export.orphans);

            Assert.NotNull(export.topFanIn);
            Assert.Equal("0x00002000", export.topFanIn![0].addr);
            Assert.Equal(2, export.topFanIn[0].count);

            Assert.NotNull(export.topFanOut);
            // A and B both have out-degree 1; deterministic tie-break by address.
            Assert.Equal("0x00001000", export.topFanOut![0].addr);
            Assert.Equal("0x00001100", export.topFanOut[1].addr);
        }
    }
}
