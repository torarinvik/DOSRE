using System;
using System.Collections.Generic;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Mc1LifterTests
    {
        [Fact]
        public void LiftMc0ToMc1_Adds_Interrupt_Consts_And_Rewrites_Int_Literals()
        {
            var mc0 = new Bin16Mc0.Mc0File
            {
                Source = "in-memory",
                StreamSha256 = "dummy",
                Statements = new List<Bin16Mc0.Mc0Stmt>
                {
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 0,
                        Addr = 0x00001234,
                        BytesHex = "CD21",
                        Asm = "int 0x21",
                        Mc0 = "INT(0x21)",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            Assert.Contains("const INT_DOS: u16 = 0x0021;", mc1);
            Assert.Contains("INT(INT_DOS); // @00001234 CD21", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            // Desugar must substitute the const back to 0x0021 (exact formatting may differ from original).
            Assert.Contains("INT(0x0021)", desugared);
            Assert.Contains("@00001234 CD21", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Creates_Ds_View_And_Rewrites_Simple_Mov_LoadStore()
        {
            var mc0 = new Bin16Mc0.Mc0File
            {
                Source = "in-memory",
                StreamSha256 = "dummy",
                Statements = new List<Bin16Mc0.Mc0Stmt>
                {
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 0,
                        Addr = 0x00001000,
                        BytesHex = "A1E404",
                        Asm = "mov ax, [ds:0x04E4]",
                        Mc0 = "EMITHEX(\"a1e404\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00001003,
                        BytesHex = "A3EC04",
                        Asm = "mov [ds:0x04EC], ax",
                        Mc0 = "EMITHEX(\"a3ec04\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // A DS view should be emitted and the statements rewritten to use it.
            Assert.Contains("view g04e0 at (DS, 0x04E0)", mc1);
            Assert.Contains("AX = g04e0.w04;", mc1);
            Assert.Contains("g04e0.w0C = AX;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            // Must preserve origin tags for the chain proof machinery.
            Assert.Contains("@00001000 A1E404", desugared);
            Assert.Contains("@00001003 A3EC04", desugared);

            // And it should rewrite into LOAD/STORE expressions.
            Assert.Contains("LOAD16(DS, ADD16(0x04E0, 0x0004))", desugared);
            Assert.Contains("STORE16(DS, ADD16(0x04E0, 0x000C), AX)", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Creates_Es_View_And_Rewrites_Simple_Mov_LoadStore()
        {
            var mc0 = new Bin16Mc0.Mc0File
            {
                Source = "in-memory",
                StreamSha256 = "dummy",
                Statements = new List<Bin16Mc0.Mc0Stmt>
                {
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 0,
                        Addr = 0x00002000,
                        BytesHex = "26A17000",
                        Asm = "mov ax, [es:0070h]",
                        Mc0 = "EMITHEX(\"26a17000\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00002004,
                        BytesHex = "268C1E7200",
                        Asm = "mov [es:72h], ds",
                        Mc0 = "EMITHEX(\"268c1e7200\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            Assert.Contains("view es_g0070 at (ES, 0x0070)", mc1);
            Assert.Contains("AX = es_g0070.w00;", mc1);
            Assert.Contains("es_g0070.w02 = DS;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00002000 26A17000", desugared);
            Assert.Contains("@00002004 268C1E7200", desugared);

            Assert.Contains("LOAD16(ES, ADD16(0x0070, 0x0000))", desugared);
            Assert.Contains("STORE16(ES, ADD16(0x0070, 0x0002), DS)", desugared);
        }
    }
}
