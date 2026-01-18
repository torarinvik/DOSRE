using System.Collections.Generic;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16Mc1StructurerTests
    {
        [Fact]
        public void Canonical_Wraps_IfElseGoto_Pair()
        {
            var mc1 = new Mc1.Mc1File
            {
                Source = "unit-test",
                Statements = new List<string>
                {
                    "loc_entry:",
                    "    if (JNZ()) goto loc_true; // @00000010 7503 ; jnz short loc_true",
                    "    else goto loc_false; // @00000012 E90500 ; jmp loc_false",
                    "    INT(INT_BREAKPOINT); // @00000015 CC ; int 3",
                }
            };

            var mc2 = Bin16Mc1Structurer.StructureMc1AsMc2Blocks(mc1, Bin16Mc1Structurer.StructureMode.Canonical);

            Assert.Contains("if (JNZ()) {", mc2);
            Assert.Contains("} else {", mc2);
            Assert.Contains("if (JNZ()) goto loc_true; // @00000010", mc2);
            Assert.Contains("goto loc_false; // @00000012", mc2);
        }

        [Fact]
        public void Canonical_Wraps_IfGoto_Then_Goto_As_ImplicitElse()
        {
            var mc1 = new Mc1.Mc1File
            {
                Source = "unit-test",
                Statements = new List<string>
                {
                    "loc_entry:",
                    "    if (JZ()) goto loc_a; // @00000020 7403 ; jz short loc_a",
                    "    goto loc_b; // @00000022 E90500 ; jmp loc_b",
                    "loc_a:",
                    "    INT(INT_BREAKPOINT); // @00000025 CC ; int 3",
                }
            };

            var mc2 = Bin16Mc1Structurer.StructureMc1AsMc2Blocks(mc1, Bin16Mc1Structurer.StructureMode.Canonical);

            Assert.Contains("if (JZ()) {", mc2);
            Assert.Contains("} else {", mc2);
            Assert.Contains("if (JZ()) goto loc_a; // @00000020", mc2);
            Assert.Contains("goto loc_b; // @00000022", mc2);
        }

        [Fact]
        public void Canonical_Wraps_SingleBranch_IfGoto_Without_Else()
        {
            var mc1 = new Mc1.Mc1File
            {
                Source = "unit-test",
                Statements = new List<string>
                {
                    "loc_entry:",
                    "    if (JCXZ()) goto loc_out; // @00000030 E303 ; jcxz short loc_out",
                    "loc_out:",
                    "    INT(INT_BREAKPOINT); // @00000033 CC ; int 3",
                }
            };

            var mc2 = Bin16Mc1Structurer.StructureMc1AsMc2Blocks(mc1, Bin16Mc1Structurer.StructureMode.Canonical);

            Assert.Contains("if (JCXZ()) {", mc2);
            Assert.Contains("if (JCXZ()) goto loc_out; // @00000030", mc2);
            Assert.DoesNotContain("} else {", mc2);
        }
    }
}
