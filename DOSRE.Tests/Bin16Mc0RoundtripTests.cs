using System;
using System.IO;
using System.Linq;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16Mc0RoundtripTests
    {
        [Fact]
        public void Lift_To_Mc0_Text_Roundtrips_ByteIdentity()
        {
            var asmPath = Path.Combine("Fixtures", "binlift", "sample.promoted.asm");
            Assert.True(File.Exists(asmPath));

            var mc0 = Bin16Mc0.LiftPromotedAsmToMc0(asmPath);
            Assert.NotNull(mc0);
            Assert.NotEmpty(mc0.StreamSha256);
            Assert.NotEmpty(mc0.Statements);

            var txt = Bin16Mc0.RenderMc0Text(mc0);
            var parsed = Bin16Mc0.ParseMc0Text(txt.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory");

            Bin16Mc0.VerifyByteIdentity(mc0, parsed);
        }

        [Fact]
        public void Mc0_Translator_Covers_Basics_In_Fixture()
        {
            var asmPath = Path.Combine("Fixtures", "binlift", "sample.promoted.asm");
            var mc0 = Bin16Mc0.LiftPromotedAsmToMc0(asmPath);

            // Fixture contains mov ax,cs ; mov es,ax ; int 21h ; ret
            Assert.Contains(mc0.Statements, s => s.Mc0 == "AX = CS");
            Assert.Contains(mc0.Statements, s => s.Mc0 == "ES = AX");
            Assert.Contains(mc0.Statements, s => s.Mc0 == "INT(0x21)");
            Assert.Contains(mc0.Statements, s => s.Mc0 == "RET_NEAR()" || s.Mc0 == "EMITHEX(\"c3\")");

            var reasm = Bin16Mc0.RenderDbAsm(mc0);
            var compact = new string(reasm.Where(c => !char.IsWhiteSpace(c)).ToArray());
            Assert.Contains("db8Ch,C8h", compact, StringComparison.OrdinalIgnoreCase);
        }
    }
}
