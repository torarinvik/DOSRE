using System;
using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Mc1DesugarTests
    {
        [Fact]
        public void Desugar_Rewrites_Consts_And_ViewFields_Deterministically()
        {
            var mc1Path = Path.Combine("Fixtures", "mc1", "sample.mc1");
            Assert.True(File.Exists(mc1Path));

            var mc1 = Mc1.Parse(mc1Path);
            var mc0 = Mc1.DesugarToMc0Text(mc1);

            // const BASE should expand into the view base offset used in field access.
            Assert.Contains("AX = LOAD16(DS, ADD16(0x0010, 0x0000))", mc0);
        }

        [Fact]
        public void Desugared_Mc0_Parses_With_Origins()
        {
            var mc1Path = Path.Combine("Fixtures", "mc1", "sample.mc1");
            var mc1 = Mc1.Parse(mc1Path);
            var mc0Text = Mc1.DesugarToMc0Text(mc1);

            var parsed = Bin16Mc0.ParseMc0Text(mc0Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory");
            Assert.Equal(2, parsed.Statements.Count);
            Assert.Equal(0u, parsed.Statements[0].Addr);
            Assert.Equal("8CC8", parsed.Statements[0].BytesHex);
        }
    }
}
