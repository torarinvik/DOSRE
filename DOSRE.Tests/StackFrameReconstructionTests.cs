using Xunit;

namespace DOSRE.Tests;

public class StackFrameReconstructionTests
{
    [Theory]
    [InlineData("[ebp-0x10]", "(uint32_t)(uintptr_t)(&local_10)")]
    [InlineData("dword ptr [ebp-10h]", "(uint32_t)(uintptr_t)(&local_10)")]
    [InlineData("[ebp+0x8]", "(uint32_t)(uintptr_t)(&arg_0)")]
    [InlineData("[ebp+0xC]", "(uint32_t)(uintptr_t)(&arg_1)")]
    [InlineData("[local_20]", "(uint32_t)(uintptr_t)(&local_20)")]
    [InlineData("[arg_2]", "(uint32_t)(uintptr_t)(&arg_2)")]
    [InlineData("[arg2]", "(uint32_t)(uintptr_t)(&arg_2)")]
    [InlineData("[localA]", "(uint32_t)(uintptr_t)(&local_a)")]
    public void NormalizeLeaRhsToAddressExpr_MapsFrameSlotsToStableVars(string rhsRaw, string expected)
    {
        var got = DOSRE.Dasm.LEDisassembler.NormalizeLeaRhsToAddressExpr(rhsRaw);
        Assert.Equal(expected, got);
    }

    [Theory]
    [InlineData("[eax]" )]
    [InlineData("[esi+edi*4]" )]
    [InlineData("ptr_00001234" )]
    public void NormalizeLeaRhsToAddressExpr_ReturnsNullWhenNotStackSlot(string rhsRaw)
    {
        var got = DOSRE.Dasm.LEDisassembler.NormalizeLeaRhsToAddressExpr(rhsRaw);
        Assert.Null(got);
    }
}
