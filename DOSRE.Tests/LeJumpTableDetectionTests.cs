using System.Collections.Generic;
using System.Linq;
using DOSRE.Dasm;
using SharpDisasm;
using Disassembler = SharpDisasm.Disassembler;
using Xunit;

namespace DOSRE.Tests
{
    public class LeJumpTableDetectionTests
    {
        private static List<Instruction> Disassemble(byte[] code, uint baseAddress)
        {
            var dis = new Disassembler(code, ArchitectureMode.x86_32, baseAddress, true);
            return dis.Disassemble().ToList();
        }

        [Fact]
        public void TryInferJumpTableSwitchBound_Ja_IsInclusive()
        {
            // cmp eax, 5
            // ja  default
            // jmp dword ptr [eax*4 + 0x12345678]
            // ret (default)
            var code = new byte[]
            {
                0x83, 0xF8, 0x05,
                0x77, 0x07,
                0xFF, 0x24, 0x85, 0x78, 0x56, 0x34, 0x12,
                0xC3,
            };

            var baseAddr = 0x1000u;
            var ins = Disassemble(code, baseAddr);
            var jmpIdx = 2;

            Assert.True(LEDisassembler.TryInferJumpTableSwitchBound(ins, jmpIdx, "eax", out var cases, out var def));
            Assert.Equal(6, cases);
            Assert.Equal(baseAddr + 0x0Cu, def);
        }

        [Fact]
        public void TryInferJumpTableSwitchBound_Jae_IsExclusive()
        {
            // cmp eax, 5
            // jae default
            // jmp dword ptr [eax*4 + 0x12345678]
            // ret (default)
            var code = new byte[]
            {
                0x83, 0xF8, 0x05,
                0x73, 0x07,
                0xFF, 0x24, 0x85, 0x78, 0x56, 0x34, 0x12,
                0xC3,
            };

            var baseAddr = 0x2000u;
            var ins = Disassemble(code, baseAddr);
            var jmpIdx = 2;

            Assert.True(LEDisassembler.TryInferJumpTableSwitchBound(ins, jmpIdx, "eax", out var cases, out var def));
            Assert.Equal(5, cases);
            Assert.Equal(baseAddr + 0x0Cu, def);
        }

        [Fact]
        public void TryParseIndirectJmpTable_SupportsScale8Stride()
        {
            // FF 24 C5 disp32 => jmp dword ptr [eax*8 + disp32]
            var insBytes = new byte[] { 0xFF, 0x24, 0xC5, 0x78, 0x56, 0x34, 0x12 };

            Assert.True(LEDisassembler.TryParseIndirectJmpTable(insBytes, out var disp, out var idxReg, out var scale));
            Assert.Equal(0x12345678u, disp);
            Assert.Equal("eax", idxReg);
            Assert.Equal(8, scale);
        }
    }
}
