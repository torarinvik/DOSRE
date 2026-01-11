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
        }
    }
}
