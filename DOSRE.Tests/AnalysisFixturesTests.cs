using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class AnalysisFixturesTests
    {
        private static LEDisassembler.LeAnalysis MakeTinyAnalysis()
        {
            // Keep this in lockstep with Fixtures/tiny.*.json
            // Graph:
            //   A -> B, C
            //   B -> C
            //   C -> (none)
            //   D -> D (self-loop)
            //   E isolated orphan
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

            analysis.Functions[a] = new LEDisassembler.LeFunctionInfo { Start = a, InstructionCount = 10, BlockCount = 2, Calls = new() { b, c } };
            analysis.Functions[b] = new LEDisassembler.LeFunctionInfo { Start = b, InstructionCount = 5, BlockCount = 1, Calls = new() { c } };
            analysis.Functions[c] = new LEDisassembler.LeFunctionInfo { Start = c, InstructionCount = 1, BlockCount = 1, Calls = new() };
            analysis.Functions[d] = new LEDisassembler.LeFunctionInfo { Start = d, InstructionCount = 2, BlockCount = 1, Calls = new() { d } };
            analysis.Functions[e] = new LEDisassembler.LeFunctionInfo { Start = e, InstructionCount = 3, BlockCount = 1, Calls = new() };

            // Minimal CFG snapshot for report counts.
            foreach (var fn in analysis.Functions.Keys)
            {
                var cfg = new LEDisassembler.LeFunctionCfg { FunctionStart = fn };
                cfg.Blocks[fn] = new LEDisassembler.LeBasicBlockInfo { Start = fn, Successors = new() };
                analysis.CfgByFunction[fn] = cfg;
            }

            // Add a couple of CFG edges for deterministic edge count.
            analysis.CfgByFunction[a].Blocks[a].Successors.Add(b);
            analysis.CfgByFunction[a].Blocks[a].Successors.Add(c);
            analysis.CfgByFunction[b].Blocks[b].Successors.Add(c);

            return analysis;
        }

        private static JsonSerializerOptions StableJsonOptions() => new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static string ReadFixture(string relativePath)
        {
            // Fixtures are copied to the test output folder.
            var baseDir = AppContext.BaseDirectory;
            var path = Path.Combine(baseDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(path), $"Missing fixture file: {path}");
            return File.ReadAllText(path).Replace("\r\n", "\n");
        }

        private static string Serialize<T>(T payload)
        {
            var json = JsonSerializer.Serialize(payload, StableJsonOptions());
            return json.Replace("\r\n", "\n") + "\n";
        }

        [Fact]
        public void Fixture_CallGraphJson_IsStable()
        {
            var analysis = MakeTinyAnalysis();
            var payload = LeExports.BuildCallGraphExport(analysis);

            var actual = Serialize(payload);
            var expected = ReadFixture("Fixtures/tiny.callgraph.json");

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void Fixture_ReportJson_IsStable()
        {
            var analysis = MakeTinyAnalysis();
            var payload = LeExports.BuildReportExport(analysis);

            var actual = Serialize(payload);
            var expected = ReadFixture("Fixtures/tiny.report.json");

            Assert.Equal(expected, actual);
        }
    }
}
