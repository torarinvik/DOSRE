using Xunit;

namespace DOSRE.Tests;

public class FlagsResultConditionTests
{
    [Fact]
    public void MakeConditionFromPendingForTest_JzFromLastResult_EmitsZeroCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jz",
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
            lastWasResult: true,
            lastResultExpr: "eax");

        Assert.Equal("eax == 0", got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JnzFromLastResult_EmitsNonZeroCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jnz",
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
            lastWasResult: true,
            lastResultExpr: "ecx");

        Assert.Equal("ecx != 0", got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JsFromLastResult_EmitsSignedCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "js",
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
            lastWasResult: true,
            lastResultExpr: "eax");

        Assert.Equal("(int32_t)eax < 0", got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JsFromLastResult_8Bit_UsesInt8Cast()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "js",
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
            lastWasResult: true,
            lastResultExpr: "al");

        Assert.Equal("(int8_t)(uint8_t)(al) < 0", got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JnsFromLastResult_EmitsSignedCheck()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jns",
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
            lastWasResult: true,
            lastResultExpr: "edx");

        Assert.Equal("(int32_t)edx >= 0", got);
    }

    [Fact]
    public void MakeConditionFromPendingForTest_JnsFromLastResult_16Bit_UsesInt16Cast()
    {
        var got = DOSRE.Dasm.LEDisassembler.MakeConditionFromPendingForTest(
            jcc: "jns",
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
            lastWasResult: true,
            lastResultExpr: "ax");

        Assert.Equal("(int16_t)(uint16_t)(ax) >= 0", got);
    }
}
