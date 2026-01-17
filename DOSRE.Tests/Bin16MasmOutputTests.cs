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
                // We emit a raw-binary org to avoid leading padding in raw-bin link mode.
                Assert.Contains("org 0000h", output);
                // But keep the intended load origin for analysis as a comment.
                Assert.Contains("logical origin: 0100h", output);
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
                // Mnemonic output needs 386 features, but must still be assembled as 16-bit code.
                Assert.Contains(".386", output);
                Assert.Contains("segment use16", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("org 0000h", output);
                Assert.Contains("logical origin: 0100h", output);
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

        [Fact]
        public void Bin16_MasmCompat_SafeMnemonicMode_FallsBackToDbForAmbiguousEncodings()
        {
            // sub ax, ax      => 29 C0  (assembler may choose 2B C0 for the same text)
            // add ax, 20h     => 05 20 00 (assembler may choose 83 C0 20 for the same text)
            // mov bx, ax      => 89 C3  (assembler may choose 8B D8 for the same text)
            // ret             => C3
            var bytes = new byte[] { 0x29, 0xC0, 0x05, 0x20, 0x00, 0x89, 0xC3, 0xC3 };

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
                    masmCompatEmitInstructionsSafe: true,
                    masmCompatEmitInstructionComments: false,
                    masmCompatEmitCodeMap: false,
                    bin16LooseIntHeuristics: false,
                    bin16LooseIoHeuristics: false,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                // Ambiguous ones should be db, but keep mnemonic as comment for readability.
                Assert.Contains("db 29h,0C0h", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("sub ax, ax", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("db 05h,20h,00h", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("add ax, 20h", output, StringComparison.OrdinalIgnoreCase);

                Assert.Contains("db 89h,0C3h", output, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("mov bx, ax", output, StringComparison.OrdinalIgnoreCase);

                // Unambiguous instruction should still be emitted as a mnemonic statement.
                Assert.DoesNotContain("db C3h", output, StringComparison.OrdinalIgnoreCase);
                Assert.Matches(new Regex(@"^\s+ret\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);

                // Ensure we didn't emit those ambiguous mnemonics as code statements.
                Assert.DoesNotMatch(new Regex(@"^\s+sub\s+ax\s*,\s*ax\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
                Assert.DoesNotMatch(new Regex(@"^\s+add\s+ax\s*,\s*20h\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
                Assert.DoesNotMatch(new Regex(@"^\s+mov\s+bx\s*,\s*ax\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }

        [Fact]
        public void Bin16_MasmCompat_SafeMnemonicMode_CanDisableImmWidthFallback()
        {
            // add ax, 20h => 05 20 00 (assembler might choose 83 C0 20 if allowed)
            // ret         => C3
            var bytes = new byte[] { 0x05, 0x20, 0x00, 0xC3 };

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
                    masmCompatEmitInstructionsSafe: true,
                    masmCompatEmitInstructionsSafeFallbacks: Bin16Disassembler.Bin16SafeMnemonicFallbacks.RegReg | Bin16Disassembler.Bin16SafeMnemonicFallbacks.Jumps,
                    masmCompatEmitInstructionsSafeForceJumps: false,
                    masmCompatEmitInstructionComments: false,
                    masmCompatEmitCodeMap: false,
                    bin16LooseIntHeuristics: false,
                    bin16LooseIoHeuristics: false,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                // With ImmWidth fallback disabled, this should be emitted as a mnemonic line, not db.
                Assert.Matches(new Regex(@"^\s+add\s+ax\s*,\s*20h\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
                Assert.DoesNotContain("db 05h,20h,00h", output, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }

        [Fact]
        public void Bin16_MasmCompat_SafeMnemonicMode_CanForceJumpSizesToEmitMnemonics()
        {
            // jmp short +0 => EB 00
            // ret          => C3
            var bytes = new byte[] { 0xEB, 0x00, 0xC3 };

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
                    masmCompatEmitInstructionsSafe: true,
                    masmCompatEmitInstructionsSafeFallbacks: Bin16Disassembler.Bin16SafeMnemonicFallbacks.Default,
                    masmCompatEmitInstructionsSafeForceJumps: true,
                    masmCompatEmitInstructionComments: false,
                    masmCompatEmitCodeMap: false,
                    bin16LooseIntHeuristics: false,
                    bin16LooseIoHeuristics: false,
                    out var output,
                    out var error);

                Assert.True(ok);
                Assert.True(string.IsNullOrWhiteSpace(error));

                // In safe mode, JMP is normally db due to short/near ambiguity; with forcing enabled it should be mnemonic.
                Assert.Matches(new Regex(@"^\s+jmp\s+short\b", RegexOptions.Multiline | RegexOptions.IgnoreCase), output);
                Assert.DoesNotContain("db EBh,00h", output, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* ignore */ }
            }
        }
    }
}
