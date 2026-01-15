using System;
using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class Bin16MasmOutputTests
    {
        [Fact]
        public void Bin16_MasmCompat_Output_HasNoCStyleHexAndHasProlog()
        {
            // mov byte ptr [1234h], 1  => C6 06 34 12 01
            // ret                       => C3
            var bytes = new byte[] { 0xC6, 0x06, 0x34, 0x12, 0x01, 0xC3 };

            var tmp = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(tmp, bytes);

                var ok = Bin16Disassembler.TryDisassembleToString(
                    tmp,
                    origin: 0x100,
                    bytesLimit: null,
                    masmCompat: true,
                    binInsights: false,
                    emitInlineStringLabels: false,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                Assert.Contains(".8086", output);
                Assert.Contains(".model tiny", output);
                Assert.Contains(".code", output);
                Assert.Contains("org 0100h", output);
                Assert.Contains("end start", output);

                // MASM/WASM should not see any 0x... literals.
                Assert.DoesNotContain("0x", output, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }
    }
}
