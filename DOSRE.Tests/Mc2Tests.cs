using System;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Mc2Tests
    {
        [Fact]
        public void Mc2_Region_Lowers_To_Mc1_Primitive_View_And_Desugars_To_Mc0_LoadStore()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "region R in DS {",
                "  foo : u16 at 0x1234;",
                "};",
                "",
                "AX = R.foo; // @00001000 DEADBEEF ; mov ax, [ds:0x1234]",
                "R.foo = AX; // @00001002 FEEDBEEF ; mov [ds:0x1234], ax",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            var mc1Text = Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes);

            // MC2 lowering must introduce a deterministic view name and rewrite the tokens.
            Assert.Contains("view _r_R_foo at (DS, 0x1234) : u16;", mc1Text);
            Assert.Contains("AX = _r_R_foo;", mc1Text);
            Assert.Contains("_r_R_foo = AX;", mc1Text);

            // MC1 desugar must lower the primitive view-name reads/writes to LOAD/STORE.
            var mc1 = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var mc0Text = Mc1.DesugarToMc0Text(mc1);

            Assert.Contains("AX = LOAD16(DS, 0x1234); // @00001000", mc0Text);
            Assert.Contains("STORE16(DS, 0x1234, AX); // @00001002", mc0Text);
        }

        [Fact]
        public void Mc2_Region_Const_Field_Is_ReadOnly()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "region R in DS {",
                "  foo : u16 at 0x1234 const;",
                "};",
                "R.foo = AX; // @00001000 DEADBEEF ; write should fail",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            Assert.ThrowsAny<Exception>(() => Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes));
        }

        [Fact]
        public void Mc2_Enum_Lowers_To_Mc1_Consts_And_Rewrites_Tag_Uses()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "enum E : u16 {",
                "  A = 0x0001;",
                "  B = 2;",
                "};",
                "AX = E.A; // @00001000 DEADBEEF ; mov ax, 1",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            var mc1Text = Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes);

            Assert.Contains("const E_A: u16 = 0x0001;", mc1Text);
            Assert.Contains("const E_B: u16 = 2;", mc1Text);
            Assert.Contains("AX = E_A; // @00001000", mc1Text);

            var mc1 = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var mc0Text = Mc1.DesugarToMc0Text(mc1);

            // Const substitution happens during MC1 desugar.
            Assert.Contains("AX = 0x0001; // @00001000", mc0Text);
        }
    }
}
