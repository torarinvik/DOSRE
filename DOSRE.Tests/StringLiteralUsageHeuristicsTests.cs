using System.Collections.Generic;
using SharpDisasm;
using SharpDisasm.Udis86;
using Xunit;

namespace DOSRE.Tests
{
    public class StringLiteralUsageHeuristicsTests
    {
        private static List<Instruction> Disassemble(byte[] code, uint baseAddress)
        {
            var dis = new Disassembler(code, ArchitectureMode.x86_32, baseAddress, true);
            return new List<Instruction>(dis.Disassemble());
        }

        [Fact]
        public void TryAnnotateCallStringLiteralArgs_PushImm32_ResolvesArgOrder()
        {
            // push 0x00002000
            // push 0x00002010
            // call +0
            var code = new byte[]
            {
                0x68, 0x00, 0x20, 0x00, 0x00,
                0x68, 0x10, 0x20, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
            };

            var instructions = Disassemble(code, 0x1000);
            var callIdx = instructions.Count - 1;

            var stringSymbols = new Dictionary<uint, string>
            {
                [0x00002000] = "s_00002000",
                [0x00002010] = "s_00002010",
            };

            var stringPreview = new Dictionary<uint, string>
            {
                [0x00002000] = "first",
                [0x00002010] = "second",
            };

            var hint = DOSRE.Dasm.LEDisassembler.TryAnnotateCallStringLiteralArgsForTest(
                instructions,
                callIdx,
                stringSymbols,
                stringPreview);

            Assert.Contains("STRARGS:", hint);
            // arg0 is the *last* push before the call (cdecl-style)
            Assert.Contains("arg0=s_00002010\"", hint.Replace(" ", ""));
            Assert.Contains("\"second\"", hint);
            Assert.Contains("arg1=s_00002000\"", hint.Replace(" ", ""));
            Assert.Contains("\"first\"", hint);
        }

        [Fact]
        public void TryAnnotateCallStringLiteralArgs_PushRegister_ResolvesThroughMovImm32()
        {
            // mov eax, 0x00002000
            // push eax
            // call +0
            var code = new byte[]
            {
                0xB8, 0x00, 0x20, 0x00, 0x00,
                0x50,
                0xE8, 0x00, 0x00, 0x00, 0x00,
            };

            var instructions = Disassemble(code, 0x2000);
            var callIdx = instructions.Count - 1;

            var stringSymbols = new Dictionary<uint, string>
            {
                [0x00002000] = "s_00002000",
            };

            var stringPreview = new Dictionary<uint, string>
            {
                [0x00002000] = "via_reg",
            };

            var hint = DOSRE.Dasm.LEDisassembler.TryAnnotateCallStringLiteralArgsForTest(
                instructions,
                callIdx,
                stringSymbols,
                stringPreview);

            Assert.Contains("STRARGS:", hint);
            Assert.Contains("s_00002000", hint);
            Assert.Contains("\"via_reg\"", hint);
        }

        [Fact]
        public void TryAnnotateCallStringLiteralArgs_StackSlotWrite_ResolvesMovEspPlusDispImm32()
        {
            // sub esp, 0x8
            // mov dword [esp+0x4], 0x00002000
            // call +0
            var code = new byte[]
            {
                0x83, 0xEC, 0x08,
                0xC7, 0x44, 0x24, 0x04, 0x00, 0x20, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
            };

            var instructions = Disassemble(code, 0x3000);
            var callIdx = instructions.Count - 1;

            var stringSymbols = new Dictionary<uint, string>
            {
                [0x00002000] = "s_00002000",
            };

            var stringPreview = new Dictionary<uint, string>
            {
                [0x00002000] = "stack_slot",
            };

            var hint = DOSRE.Dasm.LEDisassembler.TryAnnotateCallStringLiteralArgsForTest(
                instructions,
                callIdx,
                stringSymbols,
                stringPreview);

            Assert.Contains("STRARGS:", hint);
            Assert.Contains("[esp+0x4]", hint);
            Assert.Contains("s_00002000", hint);
            Assert.Contains("\"stack_slot\"", hint);
        }
    }
}
