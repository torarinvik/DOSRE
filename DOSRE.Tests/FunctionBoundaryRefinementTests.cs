using System;
using System.Collections.Generic;
using System.Linq;
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

    [Fact]
    public void NormalizePostRetZeroPaddingToNops_RetThenZero_DoesNotSwallowPrologByte()
    {
        // Real-world failure mode this targets:
        //   ret
        //   00        (padding)
        //   53 51 ... (real code)
        // Linear decode starting at the 0x00 can produce `add [ebx+0x51], dl` (00 53 51)
        // and then all subsequent code is shifted.

        var code = new byte[]
        {
            0xC3,       // ret
            0x00,       // padding byte
            0x52,       // push edx (representative real prologue byte)
            0x83, 0xEC, 0x04, // sub esp, 4
            0xC3,       // ret
        };

        const uint baseAddress = 0x1000;

        var decode = (byte[])code.Clone();
        var normalizedAddrs = new HashSet<uint>();
        var count = DOSRE.Dasm.LEDisassembler.NormalizePostRetZeroPaddingToNops(decode, baseAddress, normalizedAddrs, maxRun: 8);

        Assert.Equal(1, count);
        Assert.Equal(0x90, decode[1]);
        Assert.Contains(baseAddress + 1, normalizedAddrs);

        var disassembler = new Disassembler(
            decode,
            ArchitectureMode.x86_32,
            baseAddress,
            vendor: Vendor.Any);

        var instructions = disassembler.Disassemble().ToList();

        // We expect the normalized 0x00 padding byte to decode as a `nop`,
        // and for the next byte (the real prologue) to remain aligned.
        Assert.True(instructions.Count >= 3);
        Assert.StartsWith("ret", (instructions[0].ToString()?.Trim() ?? string.Empty), StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("nop", (instructions[1].ToString()?.Trim() ?? string.Empty), StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith("push edx", (instructions[2].ToString()?.Trim() ?? string.Empty), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NormalizePostRetZeroPaddingToNops_RetImm16ThenZero_DoesNotModifyImmediate()
    {
        // Ensure we only normalize bytes AFTER the ret imm16, not the imm16 itself.
        //   C2 0C 00   ret 0x0C
        //   00         padding
        //   53 51 ...  real code

        var code = new byte[]
        {
            0xC2, 0x0C, 0x00, // ret 0x000C
            0x00,             // padding byte after the ret instruction
            0x53, 0x51,       // push ebx; push ecx
            0xC3,
        };

        const uint baseAddress = 0x2000;

        var decode = (byte[])code.Clone();
        var normalizedAddrs = new HashSet<uint>();
        var count = DOSRE.Dasm.LEDisassembler.NormalizePostRetZeroPaddingToNops(decode, baseAddress, normalizedAddrs, maxRun: 8);

        Assert.Equal(1, count);
        Assert.Equal(0x00, decode[2]); // imm16 low byte must remain intact
        Assert.Equal(0x90, decode[3]); // padding after ret normalized
        Assert.Contains(baseAddress + 3, normalizedAddrs);

        var disassembler = new Disassembler(
            decode,
            ArchitectureMode.x86_32,
            baseAddress,
            vendor: Vendor.Any);

        var instructions = disassembler.Disassemble().ToList();

        Assert.Contains(instructions, ins =>
            (uint)ins.Offset == baseAddress + 4 &&
            (ins.ToString()?.Trim() ?? string.Empty).StartsWith("push ebx", StringComparison.OrdinalIgnoreCase));
    }
}
