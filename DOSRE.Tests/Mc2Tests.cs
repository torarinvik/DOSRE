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

        [Fact]
        public void Mc2_For_Lowers_To_Labels_And_Gotos_With_BreakContinue_Rewritten()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "for (AX = 0; AX < 3; AX = ADD16(AX, 1)) {",
                "  continue;",
                "  break;",
                "}",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            var mc1Text = Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes);

            // Deterministic labels
            Assert.Contains("_L_for_1_test:", mc1Text);
            Assert.Contains("_L_for_1_body:", mc1Text);
            Assert.Contains("_L_for_1_step:", mc1Text);
            Assert.Contains("_L_for_1_end:", mc1Text);

            // break/continue rewritten
            Assert.Contains("goto _L_for_1_step;", mc1Text);
            Assert.Contains("goto _L_for_1_end;", mc1Text);

            // Sanity: still parseable as MC1 text (even though it's non-origin control scaffolding).
            var mc1 = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            Assert.NotNull(mc1);
        }

        [Fact]
        public void Mc2_Switch_Requires_Origin_In_PreserveBytes()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "switch (AX) {",
                "  case 0: { }",
                "}",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            Assert.ThrowsAny<Exception>(() => Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes));
        }

        [Fact]
        public void Mc2_Switch_With_Origin_Lowers_To_Case_Labels_And_Remains_Parseable_To_Mc0()
        {
            var mc2Text = string.Join("\n", new[]
            {
                "@origin(0x1000..0x1010)",
                "switch (AX) {",
                "  case 0: {",
                "    AX = 0x0001; // @00001000 DEADBEEF ; mov ax, 1",
                "  }",
                "  default: {",
                "    AX = 0x0002; // @00001002 FEEDBEEF ; mov ax, 2",
                "  }",
                "}",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            var mc1Text = Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes);

            Assert.Contains("_L_switch_1_case_0x0000:", mc1Text);
            Assert.Contains("_L_switch_1_default:", mc1Text);

            var mc1 = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var mc0Text = Mc1.DesugarToMc0Text(mc1);

            // Must be parseable as MC0: only label-only lines + origin-tagged statements.
            var mc0 = Bin16Mc0.ParseMc0Text(mc0Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc0");
            Assert.True(mc0.Statements.Count >= 2);
        }

        [Fact]
        public void Mc2_Block_If_While_Wrappers_Are_ProofSafe_In_PreserveBytes()
        {
            // These constructs are presentation-only in PreserveBytes mode:
            // they must desugar to comments + the original origin-bearing statements.
            var mc2Text = string.Join("\n", new[]
            {
                "block Entry {",
                "  AX = 0x0001; // @00001000 DEADBEEF ; mov ax, 1",
                "  if (JZ()) {",
                "    BX = 0x0002; // @00001002 FEEDBEEF ; mov bx, 2",
                "  } else {",
                "    CX = 0x0003; // @00001004 BAADF00D ; mov cx, 3",
                "  }",
                "  while (JNZ()) {",
                "    DX = 0x0004; // @00001006 0D15EA5E ; mov dx, 4",
                "  }",
                "}",
            });

            var mc2 = Mc2.ParseLines(mc2Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc2");
            var mc1Text = Mc2.DesugarToMc1Text(mc2, Mc2.Mode.PreserveBytes);

            var mc1 = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var mc0Text = Mc1.DesugarToMc0Text(mc1);

            // Must be parseable as MC0: only origin-tagged statements (comments are ignored).
            var mc0 = Bin16Mc0.ParseMc0Text(mc0Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc0");
            Assert.Equal(4, mc0.Statements.Count);
        }
    }
}
