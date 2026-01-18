using System;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16Mc0CanonicalOptimizerTests
    {
        [Fact]
        public void OptimizeInvertJccSkipJmp_Rewrites_JccPlusJmp_WhenThenIsFallthrough()
        {
            var lines = new[]
            {
                "loc_entry:",
                "if (JNZ()) goto loc_then; // @00000100 7503 ; jnz short loc_then",
                "else goto loc_else; // @00000102 E90B00 ; jmp loc_else",
                "loc_then:",
                "INT(INT_BREAKPOINT); // @00000105 CC ; int 3",
                "loc_else:",
                "INT(INT_BREAKPOINT); // @00000110 CC ; int 3",
            };

            var mc0 = Bin16Mc0.ParseMc0Text(lines, sourceName: "unit-test");
            var res = Bin16Mc0CanonicalOptimizer.OptimizeInvertJccSkipJmp(mc0);

            Assert.Equal(1, res.Applied);

            Assert.Equal(0x00000100u, mc0.Statements[0].Addr);
            Assert.Equal("740E", mc0.Statements[0].BytesHex); // JZ +0x0E to loc_else
            Assert.Equal("if (JZ()) goto loc_else", mc0.Statements[0].Mc0);

            Assert.Equal(0x00000102u, mc0.Statements[1].Addr);
            Assert.Equal("909090", mc0.Statements[1].BytesHex);
            Assert.Equal("EMITHEX(\"909090\")", mc0.Statements[1].Mc0);
        }

        [Fact]
        public void OptimizeInvertJccSkipJmp_Skips_WhenElseOutOfShortRange()
        {
            var lines = new[]
            {
                "loc_entry:",
                "if (JNZ()) goto loc_then; // @00000100 7503 ; jnz short loc_then",
                "else goto loc_else; // @00000102 E9FB00 ; jmp loc_else",
                "loc_then:",
                "INT(INT_BREAKPOINT); // @00000105 CC ; int 3",
                // Put else far away so A+2->else doesn't fit in sbyte.
                "loc_else:",
                "INT(INT_BREAKPOINT); // @00000300 CC ; int 3",
            };

            var mc0 = Bin16Mc0.ParseMc0Text(lines, sourceName: "unit-test");
            var res = Bin16Mc0CanonicalOptimizer.OptimizeInvertJccSkipJmp(mc0);

            Assert.Equal(0, res.Applied);
            Assert.Equal("7503", mc0.Statements[0].BytesHex);
            Assert.StartsWith("if (JNZ())", mc0.Statements[0].Mc0, StringComparison.Ordinal);
        }

        [Fact]
        public void OptimizeElideJmpToFallthrough_Replaces_GotoNext_WithNops()
        {
            var lines = new[]
            {
                "loc_00000100:",
                "goto loc_00000103; // @00000100 E90100 ; jmp loc_00000103",
                "INT(INT_BREAKPOINT); // @00000103 CC ; int 3",
            };

            var mc0 = Bin16Mc0.ParseMc0Text(lines, sourceName: "unit-test");
            var res = Bin16Mc0CanonicalOptimizer.OptimizeElideJmpToFallthrough(mc0);

            Assert.Equal(1, res.Applied);
            Assert.Equal("909090", mc0.Statements[0].BytesHex);
            Assert.Equal("EMITHEX(\"909090\")", mc0.Statements[0].Mc0);
        }

        [Fact]
        public void OptimizeElideJccToFallthrough_Replaces_ShortJccNext_WithNops()
        {
            var lines = new[]
            {
                "loc_00000100:",
                "if (JZ()) goto loc_00000102; // @00000100 7400 ; jz short loc_00000102",
                "INT(INT_BREAKPOINT); // @00000102 CC ; int 3",
            };

            var mc0 = Bin16Mc0.ParseMc0Text(lines, sourceName: "unit-test");
            var res = Bin16Mc0CanonicalOptimizer.OptimizeElideJccToFallthrough(mc0);

            Assert.Equal(1, res.Applied);
            Assert.Equal("9090", mc0.Statements[0].BytesHex);
            Assert.Equal("EMITHEX(\"9090\")", mc0.Statements[0].Mc0);
        }
    }
}
