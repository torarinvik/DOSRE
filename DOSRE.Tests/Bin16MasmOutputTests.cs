using System;
using System.IO;
using System.Text.RegularExpressions;
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

        [Fact]
        public void Bin16_MasmCompat_InstructionOutput_EmitsMnemonics()
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
                    masmCompatEmitInstructions: true,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                // Still a MASM/WASM-friendly prolog.
                Assert.Contains(".686", output);
                Assert.Contains("org 0100h", output);
                Assert.Contains("end start", output);

                // Should show decoded mnemonics (best-effort), not just db-lines.
                Assert.Contains("mov", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("ret", output, StringComparison.OrdinalIgnoreCase);

                // Avoid C-style hex in MASM mode.
                Assert.DoesNotContain("0x", output, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }

        [Fact]
        public void Bin16_MasmCompat_BytePerfectMnemonicComments_EmitsOnlyDbButHasMnemonicsInComments()
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
                    masmCompatEmitInstructions: false,
                    masmCompatEmitInstructionComments: true,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                // Still a MASM/WASM-friendly prolog.
                Assert.Contains(".8086", output);
                Assert.Contains("org 0000h", output);
                Assert.Contains("end start", output);

                // Should keep bytes as db-lines.
                Assert.Contains("db ", output, StringComparison.OrdinalIgnoreCase);

                // But include decoded mnemonics as comments for readability.
                Assert.Contains(" mov", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains(" ret", output, StringComparison.OrdinalIgnoreCase);

                // Ensure we are not emitting instruction statements as code (only as comments).
                // i.e., no lines starting with whitespace + mnemonic.
                Assert.DoesNotMatch(new Regex(@"^\s+mov\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
                Assert.DoesNotMatch(new Regex(@"^\s+ret\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }

        [Fact]
        public void Bin16_MasmCompat_CodeMap_EmitsCodeMapSection()
        {
            // Small program with a branch so reachability has something to report.
            //   jmp short +1  => EB 01
            //   nop           => 90
            //   ret           => C3
            var bytes = new byte[] { 0xEB, 0x01, 0x90, 0xC3 };

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
                    masmCompatEmitInstructions: false,
                    masmCompatEmitInstructionComments: true,
                    masmCompatEmitCodeMap: true,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                Assert.Contains("CODE MAP", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("code:", output, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }
    }
}
