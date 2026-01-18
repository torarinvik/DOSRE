using System;
using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests;

public class Bin16Mc0TemplatePatchTests
{
    [Fact]
    public void RenderDbAsmFromPromotedTemplate_Can_Allow_ByteMismatch_While_Enforcing_Length()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dosre-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var template = Path.Combine(dir, "t.promoted.wasm.asm");
            File.WriteAllText(template, string.Join("\n", new[]
            {
                "db 0ABh ; 00000000h AB ; db 0xAB",
                "db 0CDh ; 00000001h CD ; db 0xCD",
            }) + "\n");

            var mc0 = new Bin16Mc0.Mc0File
            {
                Source = "in-memory",
                StreamSha256 = "deadbeef",
                Statements =
                {
                    new Bin16Mc0.Mc0Stmt { Addr = 0x00000000, BytesHex = "AC" },
                    new Bin16Mc0.Mc0Stmt { Addr = 0x00000001, BytesHex = "CD" },
                }
            };

            Assert.ThrowsAny<Exception>(() => Bin16Mc0.RenderDbAsmFromPromotedTemplate(template, mc0, allowByteMismatch: false));

            var asm = Bin16Mc0.RenderDbAsmFromPromotedTemplate(template, mc0, allowByteMismatch: true);
            Assert.Contains("db 0ACh", asm);
            Assert.Contains("db 0CDh", asm);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
