using Xunit;

namespace DOSRE.Tests;

public class StackFrameReconstructionTests
{
    [Theory]
    [InlineData("[ebp-0x10]", "(ebp - 0x10u)")]
    [InlineData("dword ptr [ebp-10h]", "(ebp - 0x10u)")]
    [InlineData("[ebp+0x8]", "(ebp + 0x8u)")]
    [InlineData("[ebp+0xC]", "(ebp + 0xCu)")]
    [InlineData("[local_20]", "(ebp - 0x20u)")]
    [InlineData("[arg_2]", "(ebp + 0x10u)")]
    [InlineData("[arg2]", "(ebp + 0x10u)")]
    [InlineData("[localA]", "(ebp - 0xAu)")]
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
