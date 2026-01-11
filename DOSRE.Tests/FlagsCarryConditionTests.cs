using Xunit;

namespace DOSRE.Tests;

public class FlagsCarryConditionTests
{
    [Fact]
    public void MakeConditionFromPendingForTest_JcAfterAdd_EmitsCarryCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jc",
            lastWasCmp: false,
            cmpLhs: null,
            cmpRhs: null,
            lastWasTest: false,
            testLhs: null,
            testRhs: null,
            lastWasIncDec: false,
            incDecOperand: null,
            lastWasArith: false,
            arithOp: null,
            arithA: null,
            arithB: null,
            lastWasCarry: true,
            carryOp: "add",
            carryA: "eax",
            carryB: "1",
            carryIn: "0");

        var expected = "((uint64_t)(uint32_t)(eax) + (uint64_t)(uint32_t)(1) + (uint64_t)(uint32_t)(0)) > 0xFFFFFFFFULL";
        Assert.Equal(expected, got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JncAfterSub_NegatesBorrowCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jnc",
            lastWasCmp: false,
            cmpLhs: null,
            cmpRhs: null,
            lastWasTest: false,
            testLhs: null,
            testRhs: null,
            lastWasIncDec: false,
            incDecOperand: null,
            lastWasArith: false,
            arithOp: null,
            arithA: null,
            arithB: null,
            lastWasCarry: true,
            carryOp: "sub",
            carryA: "eax",
            carryB: "ecx",
            carryIn: "0");

        var inner = "(uint64_t)(uint32_t)(eax) < ((uint64_t)(uint32_t)(ecx) + (uint64_t)(uint32_t)(0))";
        Assert.Equal($"!({inner})", got);
    }
}
