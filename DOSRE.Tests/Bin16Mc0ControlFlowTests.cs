using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16Mc0ControlFlowTests
    {
        [Fact]
        public void Mc0_Translator_Lifts_ControlFlow_Mnemonics()
        {
            var asmPath = Path.Combine("Fixtures", "binlift", "controlflow.promoted.asm");
            Assert.True(File.Exists(asmPath));

            var mc0 = Bin16Mc0.LiftPromotedAsmToMc0(asmPath);

            Assert.Contains(mc0.Statements, s => s.Mc0 == "if (JCXZ()) goto loc_00000006");
            Assert.Contains(mc0.Statements, s => s.Mc0 == "if (LOOP()) goto loc_00000000");
            Assert.Contains(mc0.Statements, s => s.Mc0 == "if (JP()) goto loc_00000006");
        }
    }
}
