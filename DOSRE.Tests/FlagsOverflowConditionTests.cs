using Xunit;

namespace DOSRE.Tests;

public class FlagsOverflowConditionTests
{
    [Fact]
    public void MakeConditionFromPendingForTest_JoAfterAdd_EmitsOverflowCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jo",
            lastWasCmp: false,
            cmpLhs: null,
            cmpRhs: null,
            lastWasTest: false,
            testLhs: null,
            testRhs: null,
            lastWasIncDec: false,
            incDecOperand: null,
            lastWasArith: true,
            arithOp: "add",
            arithA: "eax",
            arithB: "1");

        var expected = "(((int64_t)(int32_t)(eax) + (int64_t)(int32_t)(1)) > 0x7fffffffLL) || (((int64_t)(int32_t)(eax) + (int64_t)(int32_t)(1)) < (-0x80000000LL))";
        Assert.Equal(expected, got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JnoAfterSub_NegatesOverflowCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jno",
            lastWasCmp: false,
            cmpLhs: null,
            cmpRhs: null,
            lastWasTest: false,
            testLhs: null,
            testRhs: null,
            lastWasIncDec: false,
            incDecOperand: null,
            lastWasArith: true,
            arithOp: "sub",
            arithA: "local_10",
            arithB: "ecx");

        var inner = "(((int64_t)(int32_t)(local_10) - (int64_t)(int32_t)(ecx)) > 0x7fffffffLL) || (((int64_t)(int32_t)(local_10) - (int64_t)(int32_t)(ecx)) < (-0x80000000LL))";
        Assert.Equal($"!({inner})", got);
    }
}
