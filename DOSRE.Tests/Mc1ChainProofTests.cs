using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests;

public sealed class Mc1ChainProofTests
{
    [Fact]
    public void ProveMc1DesugarsToSameMc0AsPromotedBaseline()
    {
        var promotedPath = Path.Combine("Fixtures", "binlift", "sample.promoted.asm");
        var baselineMc0 = Bin16Mc0.LiftPromotedAsmToMc0(promotedPath);

        // MC1: no extra sugar, just pass-through statements with origins.
        // This proves the chain mechanism (MC1 parse/desugar -> MC0 parse -> VerifyByteIdentity)
        // is sound for the simplest case.
        var mc1Text = Mc1Header() + Bin16Mc0.RenderMc0Text(baselineMc0);
        var mc1File = Mc1.ParseLines(mc1Text.Split(new[] { "\r\n", "\n" }, System.StringSplitOptions.None), sourceName: "inline");
        var desugared = Mc1.DesugarToMc0Text(mc1File);
        var mc1Mc0 = Bin16Mc0.ParseMc0Text(desugared.Split(new[] { "\r\n", "\n" }, System.StringSplitOptions.None), sourceName: "desugared");

        Bin16Mc0.VerifyByteIdentity(baselineMc0, mc1Mc0);
    }

    private static string Mc1Header()
    {
        return "// mc1\n";
    }
}
