using System;
using System.Collections.Generic;
using SharpDisasm;
using SharpDisasm.Udis86;
using Xunit;

namespace DOSRE.Tests;

public class FunctionBoundaryRefinementTests
{
    [Fact]
    public void RefineFunctionStartsByPrologAfterRet_AddsStartAfterRetPaddingAndProlog()
    {
        // Layout:
        // 0x1000: C3                ret
        // 0x1001: 90 90             nop; nop (padding)
        // 0x1003: 55 8B EC          push ebp; mov ebp, esp (classic prolog)
        // 0x1006: C3                ret

        var code = new byte[]
        {
            0xC3,
            0x90, 0x90,
            0x55, 0x8B, 0xEC,
            0xC3,
        };

        const uint baseAddress = 0x1000;

        var disassembler = new Disassembler(
            code,
            ArchitectureMode.x86_32,
            baseAddress,
            vendor: Vendor.Any);

        var instructions = new List<Instruction>(disassembler.Disassemble());

        var functionStarts = new HashSet<uint> { baseAddress };

        var added = DOSRE.Dasm.LEDisassembler.RefineFunctionStartsByPrologAfterRet(instructions, functionStarts);

        Assert.Equal(1, added);
        Assert.Contains(baseAddress + 3, functionStarts);
    }

    [Fact]
    public void RefineFunctionStartsByPrologAfterRet_DoesNotAddWhenNoProlog()
    {
        // Layout:
        // 0x2000: C3                ret
        // 0x2001: 90                nop
        // 0x2002: 40                inc eax (not a prolog)

        var code = new byte[]
        {
            0xC3,
            0x90,
            0x40,
        };

        const uint baseAddress = 0x2000;

        var disassembler = new Disassembler(
            code,
            ArchitectureMode.x86_32,
            baseAddress,
            vendor: Vendor.Any);

        var instructions = new List<Instruction>(disassembler.Disassemble());

        var functionStarts = new HashSet<uint> { baseAddress };

        var added = DOSRE.Dasm.LEDisassembler.RefineFunctionStartsByPrologAfterRet(instructions, functionStarts);

        Assert.Equal(0, added);
        Assert.DoesNotContain(baseAddress + 2, functionStarts);
    }
}
