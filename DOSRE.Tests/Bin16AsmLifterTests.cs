using System;
using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16AsmLifterTests
    {
        [Fact]
        public void LiftLines_ExtractsAddrBytesAndLabels()
        {
            var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "binlift", "sample.promoted.asm");
            Assert.True(File.Exists(fixture));

            var lines = File.ReadAllLines(fixture);
            var lf = Bin16AsmLifter.LiftLines(lines, fixture);

            // We expect three instruction/db nodes with addr/bytes.
            var lifted = lf.Nodes.FindAll(n => n.Kind == "insn" || n.Kind == "db");
            Assert.Equal(4, lifted.Count);

            Assert.Equal((uint)0x00000000, lifted[0].Addr);
            Assert.Equal("8CC8", lifted[0].BytesHex);

            Assert.Equal((uint)0x00000002, lifted[1].Addr);
            Assert.Equal("8EC0", lifted[1].BytesHex);

            // Label should attach to the next node (int 21h)
            Assert.Contains("loc_00000004", lifted[2].Labels);
            Assert.Equal((uint)0x00000004, lifted[2].Addr);
            Assert.Equal("CD21", lifted[2].BytesHex);

            Assert.Equal("c3", lifted[3].BytesHex.ToLowerInvariant());
            Assert.False(string.IsNullOrWhiteSpace(lf.StreamSha256));
            Assert.Equal(64, lf.StreamSha256.Length);
        }

        [Fact]
        public void LiftToFiles_WritesJsonAndC()
        {
            var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "binlift", "sample.promoted.asm");
            var tmp = Path.Combine(Path.GetTempPath(), "dosre-binlift-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tmp);

            var outJson = Path.Combine(tmp, "out.json");
            var outH = Path.Combine(tmp, "out.h");
            var outC = Path.Combine(tmp, "out.c");

            Bin16AsmLifter.LiftToFiles(fixture, outJson, outC, outH);

            Assert.True(File.Exists(outJson));
            Assert.True(File.Exists(outC));
            Assert.True(File.Exists(outH));

            var c = File.ReadAllText(outC);
            Assert.Contains("g_crude_program", c);
            Assert.Contains("stream_sha256", c);
            Assert.Contains("g_crude_blob_", c);
        }
    }
}
