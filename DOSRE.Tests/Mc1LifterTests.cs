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
            Assert.Contains("STORE8(CS, ADD16(0x0070,", desugared);
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

        [Fact]
        public void LiftMc0ToMc1_Sugars_IncDec_As_Postfix_And_Desugars_To_Assignment()
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
                        Addr = 0x00007000,
                        BytesHex = "40",
                        Asm = "inc ax",
                        Mc0 = "EMITHEX(\"40\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00007001,
                        BytesHex = "FF4AFE",
                        Asm = "dec word ptr [bp+si-2]",
                        Mc0 = "EMITHEX(\"ff4afe\")",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            Assert.Contains("AX++;", mc1);
            Assert.Contains("view mem_ss_fff0_w at (SS, 0xFFF0) : u16;", mc1);
            Assert.Contains("mem_ss_fff0_w[ADD16(ADD16(BP, SI), 0x000E)]--;", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00007000 40", desugared);
            Assert.Contains("AX = ADD(AX, 0x0001)", desugared);

            Assert.Contains("@00007001 FF4AFE", desugared);
            Assert.Contains("STORE16(SS, ADD16(0xFFF0, ADD16(ADD16(BP, SI), 0x000E)), SUB(LOAD16(SS, ADD16(0xFFF0, ADD16(ADD16(BP, SI), 0x000E))), 0x0001))", desugared);
        }

        [Fact]
        public void Mc1_AsmLike_Cmp_Lowers_And_Preserves_Origin_Tag()
        {
            var mc1 = string.Join("\n", new[]
            {
                "view mem_ss_fff0_w at (SS, 0xFFF0) : u16;",
                "    CMP AX, mem_ss_fff0_w[ADD16(ADD16(BP, SI), 0x000E)]; // @00008000 3B42FE ; cmp ax, [bp+si-2]",
            });

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);

            Assert.Contains("@00008000 3B42FE", desugared);
            Assert.Contains("CMP(AX, LOAD16(SS, ADD16(0xFFF0, ADD16(ADD16(BP, SI), 0x000E))))", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Structures_Simple_IfElse_When_Unambiguous()
        {
            // Pattern:
            //   if (JZ()) goto else
            //   ...then...
            //   goto end
            // else:
            //   ...else...
            // end:
            var mc0 = new Bin16Mc0.Mc0File
            {
                Source = "in-memory",
                StreamSha256 = "dummy",
                Statements = new List<Bin16Mc0.Mc0Stmt>
                {
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 0,
                        Addr = 0x00009000,
                        BytesHex = "7404",
                        Asm = "jz short loc_else",
                        Mc0 = "if (JZ()) goto loc_else",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00009002,
                        BytesHex = "90",
                        Asm = "nop",
                        Mc0 = "EMITHEX(\"90\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 2,
                        Addr = 0x00009003,
                        BytesHex = "EB02",
                        Asm = "jmp short loc_end",
                        Mc0 = "goto loc_end",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 3,
                        Addr = 0x00009005,
                        BytesHex = "90",
                        Asm = "nop",
                        Mc0 = "EMITHEX(\"90\")",
                        Labels = new List<string> { "loc_else" },
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 4,
                        Addr = 0x00009006,
                        BytesHex = "C3",
                        Asm = "ret",
                        Mc0 = "RET_NEAR()",
                        Labels = new List<string> { "loc_end" },
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            Assert.Contains("if (!JZ()) { // @00009000 7404", mc1);
            Assert.Contains("} else { // @00009003 EB02", mc1);
            Assert.Contains("} loc_end:", mc1);

            // Must still desugar into something MC0 can parse (origin tags intact).
            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);
            Assert.Contains("@00009000 7404", desugared);
            Assert.Contains("@00009003 EB02", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Pairs_IfGoto_Then_Goto_As_ElseGoto()
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
                        Addr = 0x00009100,
                        BytesHex = "7402",
                        Asm = "jz short loc_true",
                        Mc0 = "if (JZ()) goto loc_true",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00009102,
                        BytesHex = "EB02",
                        Asm = "jmp short loc_false",
                        Mc0 = "goto loc_false",
                        Labels = new List<string>(),
                    },
                    // Add a second incoming edge to loc_true, so the higher-level if/else block structuring
                    // stays conservative and the simple else-goto pairing can be exercised.
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 2,
                        Addr = 0x00009104,
                        BytesHex = "7200",
                        Asm = "jc short loc_true",
                        Mc0 = "if (JC()) goto loc_true",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 3,
                        Addr = 0x00009106,
                        BytesHex = "90",
                        Asm = "nop",
                        Mc0 = "EMITHEX(\"90\")",
                        Labels = new List<string> { "loc_true" },
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 4,
                        Addr = 0x00009107,
                        BytesHex = "C3",
                        Asm = "ret",
                        Mc0 = "RET_NEAR()",
                        Labels = new List<string> { "loc_false" },
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);
            Assert.Contains("else goto loc_false; // @00009102 EB02", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);
            Assert.Contains("@00009100 7402", desugared);
            Assert.Contains("@00009102 EB02", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Structures_Simple_Backedge_As_DoWhile()
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
                        Addr = 0x00009200,
                        BytesHex = "90",
                        Asm = "nop",
                        Mc0 = "EMITHEX(\"90\")",
                        Labels = new List<string> { "loc_loop" },
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x00009201,
                        BytesHex = "90",
                        Asm = "nop",
                        Mc0 = "EMITHEX(\"90\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 2,
                        Addr = 0x00009202,
                        BytesHex = "75FC",
                        Asm = "jnz short loc_loop",
                        Mc0 = "if (JNZ()) goto loc_loop",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);
            Assert.Contains("loc_loop:", mc1);
            Assert.Contains("do {", mc1);
            Assert.Contains("} while (JNZ()); // @00009202 75FC", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);
            Assert.Contains("@00009202 75FC", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Annotates_JumpTable_When_JmpReg_Is_Loaded_From_Memory()
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
                        Addr = 0x00009FFC,
                        BytesHex = "D1E3",
                        Asm = "shl bx, 1",
                        Mc0 = "EMITHEX(\"d1e3\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x0000A000,
                        BytesHex = "2E8B807200",
                        Asm = "mov ax, [cs:bx+si+72h]",
                        Mc0 = "EMITHEX(\"2e8b807200\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 2,
                        Addr = 0x0000A005,
                        BytesHex = "FFE0",
                        Asm = "jmp ax",
                        Mc0 = "goto ax",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            // Ensure the table-like indexed load is lifted.
            Assert.Contains("view mem_cs_0070_w at (CS, 0x0070) : u16;", mc1);
            Assert.Contains("AX = mem_cs_0070_w[ADD16(ADD16(BX, SI), 0x0002)];", mc1);

            // And ensure we recognize the pattern and annotate it.
            Assert.Contains("// JUMPTABLE:", mc1);
            Assert.Contains("AX <- (CS, 0x0070)", mc1);

            // The chain must still parse/desugar with origin tags intact.
            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);
            Assert.Contains("@0000A005 FFE0", desugared);
        }

        [Fact]
        public void LiftMc0ToMc1_Annotates_MaybeJumpTable_When_TableLike_Load_Lacks_Strong_Evidence()
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
                        Addr = 0x0000B000,
                        BytesHex = "2E8B4472",
                        Asm = "mov ax, [cs:si+72h]",
                        Mc0 = "EMITHEX(\"2e8b4472\")",
                        Labels = new List<string>(),
                    },
                    new Bin16Mc0.Mc0Stmt
                    {
                        Index = 1,
                        Addr = 0x0000B004,
                        BytesHex = "FFE0",
                        Asm = "jmp ax",
                        Mc0 = "goto ax",
                        Labels = new List<string>(),
                    },
                }
            };

            var mc1 = Bin16Mc1Lifter.LiftMc0ToMc1Text(mc0);

            Assert.Contains("view mem_cs_0070_w at (CS, 0x0070) : u16;", mc1);
            Assert.Contains("AX = mem_cs_0070_w[ADD16(SI, 0x0002)];", mc1);

            // No strong nearby scaling/bounds evidence, but it is table-like (indexed + displacement).
            Assert.Contains("// JUMPTABLE?:", mc1);

            var parsed = Mc1.ParseLines(mc1.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None), sourceName: "in-memory.mc1");
            var desugared = Mc1.DesugarToMc0Text(parsed);
            Assert.Contains("@0000B004 FFE0", desugared);
        }
    }
}
