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

        [Fact]
        public void LiftMc0ToMc1_Creates_Ivt_Farptr_View_For_Seg0_Word_Accesses()
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
                        Addr = 0x00003000,
                        BytesHex = "A18400",
                        Asm = "mov ax, [0000h:0084h]",
                        Mc0 = "EMITHEX(\"a18400\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00003003,
                        BytesHex = "A38600",
                        Asm = "mov [0000h:0086h], ax",
                        Mc0 = "EMITHEX(\"a38600\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // 0x0084 corresponds to vector 0x21 (0x21*4 = 0x84)
            Assert.Contains("view ivt_21 at (0x0000, 0x0084) : farptr16;", mc1);
            Assert.Contains("AX = ivt_21.off;", mc1);
            Assert.Contains("ivt_21.seg = AX;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00003000 A18400", desugared);
            Assert.Contains("@00003003 A38600", desugared);

            Assert.Contains("LOAD16(0x0000, ADD16(0x0084, 0x0000))", desugared);
            Assert.Contains("STORE16(0x0000, ADD16(0x0084, 0x0002), AX)", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Rewrites_Ds_Indexed_Mov_Using_Bracket_Sugar()
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
                        Addr = 0x00004000,
                        BytesHex = "8B814E04",
                        Asm = "mov ax, [ds:bx+di+04E4h]",
                        Mc0 = "EMITHEX(\"8b814e04\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00004004,
                        BytesHex = "89814E04",
                        Asm = "mov [ds:bx+di+04E4h], ax",
                        Mc0 = "EMITHEX(\"89814e04\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // Aligned base is 0x04E0, element type u16.
            Assert.Contains("view mem_ds_04e0_w at (DS, 0x04E0) : u16;", mc1);
            Assert.Contains("AX = mem_ds_04e0_w[ADD16(ADD16(BX, DI), 0x0004)];", mc1);
            Assert.Contains("mem_ds_04e0_w[ADD16(ADD16(BX, DI), 0x0004)] = AX;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00004000 8B814E04", desugared);
            Assert.Contains("@00004004 89814E04", desugared);

            // Bracket sugar must lower into LOAD/STORE with the effective address built via ADD16.
            Assert.Contains("LOAD16(DS, ADD16(0x04E0, ADD16(ADD16(BX, DI), 0x0004)))", desugared);
            Assert.Contains("STORE16(DS, ADD16(0x04E0, ADD16(ADD16(BX, DI), 0x0004)), AX)", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Sugars_NonMov_Memory_Ops_Using_Bracket_Sugar()
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
                        Addr = 0x00005000,
                        BytesHex = "3E0B01",
                        Asm = "or ax, [ds:bx+di]",
                        Mc0 = "EMITHEX(\"3e0b01\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00005003,
                        BytesHex = "2E205072",
                        Asm = "and [cs:bx+si+72h], dl",
                        Mc0 = "EMITHEX(\"2e205072\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // reg-only EA => base 0x0000 primitive view
            Assert.Contains("view mem_ds_0000_w at (DS, 0x0000) : u16;", mc1);
            Assert.Contains("OR AX, mem_ds_0000_w[ADD16(BX, DI)];", mc1);

            // EA with +72h => base 0x0070 primitive view
            Assert.Contains("view mem_cs_0070_b at (CS, 0x0070) : u8;", mc1);
            Assert.Contains("AND mem_cs_0070_b[ADD16(ADD16(BX, SI), 0x0002)], DL;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            // Origin tags must survive.
            Assert.Contains("@00005000 3E0B01", desugared);
            Assert.Contains("@00005003 2E205072", desugared);

            // Bracket sugar must lower into LOAD/STORE forms.
            Assert.Contains("LOAD16(DS, ADD16(0x0000, ADD16(BX, DI)))", desugared);
            Assert.Contains("STORE8(CS, ADD16(0x0070, ADD16(ADD16(BX, SI), 0x0002))", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Rewrites_Bp_Based_Indexing_Defaults_To_SS_And_Supports_Negative_Displacement()
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
                        Addr = 0x00006000,
                        BytesHex = "8A42FE",
                        Asm = "mov al, [bp+si-2]",
                        Mc0 = "EMITHEX(\"8a42fe\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // -2 => 0xFFFE, aligned base 0xFFF0, delta 0x000E.
            Assert.Contains("view mem_ss_fff0_b at (SS, 0xFFF0) : u8;", mc1);
            Assert.Contains("AL = mem_ss_fff0_b[ADD16(ADD16(BP, SI), 0x000E)];", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00006000 8A42FE", desugared);
            Assert.Contains("LOAD8(SS, ADD16(0xFFF0, ADD16(ADD16(BP, SI), 0x000E)))", desugared);
        }
    }
}
