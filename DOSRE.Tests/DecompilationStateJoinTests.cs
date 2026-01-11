using System;
using System.Collections.Generic;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests;

public class DecompilationStateJoinTests
{
    [Fact]
    public void JoinStateForTest_IntersectsRegistersByExactValue()
    {
        var aRegs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["eax"] = "1",
            ["ebx"] = "2",
            ["ecx"] = "(foo + 4)",
        };

        var bRegs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["eax"] = "1",
            ["ebx"] = "3",
            ["ecx"] = "(FOO + 4)",
            ["edx"] = "999",
        };

        var (regs, stack) = LEDisassembler.JoinStateForTest(aRegs, new List<string>(), bRegs, new List<string>());

        Assert.Empty(stack);
        Assert.Equal(2, regs.Count);
        Assert.Equal("1", regs["eax"]);
        Assert.Equal("(foo + 4)", regs["ecx"]);
        Assert.False(regs.ContainsKey("ebx"));
        Assert.False(regs.ContainsKey("edx"));
    }

    [Fact]
    public void JoinStateForTest_MergesStackSlotWise_AndMarksConflictsUnknown()
    {
        var aStack = new List<string> { "a", "b", "c" };
        var bStack = new List<string> { "A", "x", "c" };

        var (regs, stack) = LEDisassembler.JoinStateForTest(
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            aStack,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            bStack);

        Assert.Empty(regs);
        Assert.Equal(new List<string> { "a", "unk", "c" }, stack);
    }

    [Fact]
    public void JoinStateForTest_ReturnsEmptyStackWhenDepthDiffers()
    {
        var (regs, stack) = LEDisassembler.JoinStateForTest(
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            new List<string> { "a" },
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            new List<string> { "a", "b" });

        Assert.Empty(regs);
        Assert.Empty(stack);
    }

    [Fact]
    public void JoinStateForTest_HandlesNullInputs()
    {
        var (regs, stack) = LEDisassembler.JoinStateForTest(null, null, null, null);
        Assert.Empty(regs);
        Assert.Empty(stack);
    }
}
