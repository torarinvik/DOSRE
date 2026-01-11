using System;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeDecompOutputTests
    {
        [Fact]
        public void MultipartOutput_IncludesLslStub_AndBuildSh()
        {
            var asm = string.Join("\n", new[]
            {
                "; Minimal asm for pseudo-C parser",
                "func_00000000:",
                "00000000h 0F03D0 lsl edx, ax",
                "00000003h 7505 jnz loc_0000000A",
                "00000005h C3 ret",
                "loc_0000000A:",
                "0000000Ah C3 ret",
                "",
            });

            var ok = LEDisassembler.TryDecompileToMultipartFromAsm(
                asm,
                onlyFunction: null,
                chunkSize: 1,
                chunkSizeIsCount: false,
                out var files,
                out var error);

            Assert.True(ok, error);
            Assert.NotNull(files);

            Assert.True(files.ContainsKey("blst.h"), "Expected blst.h in multipart output");
            Assert.Contains("__lsl_success", files["blst.h"]);

            Assert.True(files.ContainsKey("build.sh"), "Expected build.sh in multipart output");
            Assert.Contains("cc -std=c99", files["build.sh"]);
        }
    }
}
