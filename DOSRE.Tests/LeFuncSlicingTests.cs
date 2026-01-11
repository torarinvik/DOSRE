using System;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeFuncSlicingTests
    {
        [Fact]
        public void TrySliceToSingleFunction_TruncatesAfterLastRetLikeTerminal()
        {
            var lines = new[]
            {
                "func_00010380:",
                "00010380: 90 nop",
                "00010381: C3 ret",
                "00010382: 90 nop ; decoded tail that should be dropped",
                "00010383: 90 nop ; decoded tail that should be dropped",
                "func_00010400:",
                "00010400: 90 nop",
            };

            var (ok, slice, error) = LEDisassembler.TrySliceToSingleFunctionForTest(lines, "00010380");

            Assert.True(ok, error);
            Assert.Equal(new[] { "func_00010380:", "00010380: 90 nop", "00010381: C3 ret" }, slice);
        }

        [Fact]
        public void TrySliceToSingleFunction_DoesNotTruncateWhenNoTerminalPresent()
        {
            var lines = new[]
            {
                "func_00010380:",
                "00010380: E9 00 00 00 00 jmp loc_00010390",
                "loc_00010390:",
                "00010390: 90 nop",
                "func_00010400:",
                "00010400: 90 nop",
            };

            var (ok, slice, error) = LEDisassembler.TrySliceToSingleFunctionForTest(lines, "0x00010380");

            Assert.True(ok, error);
            Assert.Equal(new[]
            {
                "func_00010380:",
                "00010380: E9 00 00 00 00 jmp loc_00010390",
                "loc_00010390:",
                "00010390: 90 nop",
            }, slice);
        }

        [Fact]
        public void TrySliceToSingleFunction_UsesLastTerminalNotFirst()
        {
            var lines = new[]
            {
                "func_00010380:",
                "00010380: 740D jz loc_00010390",
                "00010382: 90 nop",
                "00010383: C3 ret ; early return path (not safe to truncate)",
                "loc_00010390:",
                "00010390: 90 nop",
                "00010391: C3 ret ; final return",
                "00010392: 90 nop ; decoded tail that should be dropped",
                "func_00010400:",
            };

            var (ok, slice, error) = LEDisassembler.TrySliceToSingleFunctionForTest(lines, "func_00010380");

            Assert.True(ok, error);
            Assert.Equal(new[]
            {
                "func_00010380:",
                "00010380: 740D jz loc_00010390",
                "00010382: 90 nop",
                "00010383: C3 ret ; early return path (not safe to truncate)",
                "loc_00010390:",
                "00010390: 90 nop",
                "00010391: C3 ret ; final return",
            }, slice);
        }

        [Fact]
        public void TrySliceToSingleFunction_DoesNotTruncateAwayReferencedLabelAfterRet()
        {
            var lines = new[]
            {
                "func_00010380:",
                "00010380: 85C0 test eax, eax",
                "00010382: 7404 jz loc_00010388",
                "00010384: C3 ret",
                "loc_00010388:",
                "00010388: 90 nop",
                "00010389: C3 ret",
                "0001038A: 90 nop ; decoded tail that should be dropped",
                "func_00010400:",
            };

            var (ok, slice, error) = LEDisassembler.TrySliceToSingleFunctionForTest(lines, "00010380");

            Assert.True(ok, error);
            Assert.Equal(new[]
            {
                "func_00010380:",
                "00010380: 85C0 test eax, eax",
                "00010382: 7404 jz loc_00010388",
                "00010384: C3 ret",
                "loc_00010388:",
                "00010388: 90 nop",
                "00010389: C3 ret",
            }, slice);
        }
    }
}
