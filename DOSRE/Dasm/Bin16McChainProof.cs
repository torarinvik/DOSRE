using System;
using System.IO;

namespace DOSRE.Dasm;

public static class Bin16McChainProof
{
    public sealed class ProveOptions
    {
        public bool SkipRebuildCompare { get; set; }
        public string OutDir { get; set; }
        public string WasmPath { get; set; }
        public string WlinkPath { get; set; }
    }

    public sealed class ProveResult
    {
        public bool Mc1DesugarsToSameMc0 { get; set; }
        public int Mc0StatementCount { get; set; }
        public string Mc0StreamSha256 { get; set; }

        public bool? Mc0RebuildByteEqual { get; set; }
        public string Mc0RebuildOriginalSha256 { get; set; }
        public string Mc0RebuildRebuiltSha256 { get; set; }
        public string RebuiltExe { get; set; }
        public string FirstDiff { get; set; }
    }

    public static ProveResult ProveMc1AgainstPromotedAndOriginal(
        string mc1Path,
        string promotedAsmPath,
        string originalExePath,
        ProveOptions opts)
    {
        if (string.IsNullOrWhiteSpace(mc1Path)) throw new ArgumentException("mc1Path is required", nameof(mc1Path));
        if (string.IsNullOrWhiteSpace(promotedAsmPath)) throw new ArgumentException("promotedAsmPath is required", nameof(promotedAsmPath));
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        // Baseline: promoted asm -> MC0
        var baselineMc0 = Bin16Mc0.LiftPromotedAsmToMc0(promotedAsmPath);

        // MC1 -> desugared MC0 -> parse
        var mc1File = Mc1.Parse(mc1Path);
        var desugaredMc0Text = Mc1.DesugarToMc0Text(mc1File);
        var mc1Mc0 = Bin16Mc0.ParseMc0Text(
            desugaredMc0Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None),
            sourceName: mc1Path + " (desugared)");

        // Proof: strict origin stream identity
        Bin16Mc0.VerifyByteIdentity(baselineMc0, mc1Mc0);

        var res = new ProveResult
        {
            Mc1DesugarsToSameMc0 = true,
            Mc0StatementCount = baselineMc0.Statements.Count,
            Mc0StreamSha256 = baselineMc0.StreamSha256,
        };

        if (opts.SkipRebuildCompare)
            return res;

        if (string.IsNullOrWhiteSpace(originalExePath))
            throw new ArgumentException("originalExePath is required when SkipRebuildCompare is false", nameof(originalExePath));

        // Grounding proof: promoted asm -> MC0 -> reasm -> assemble/link -> byte-compare original
        var verifyOpts = new Bin16Mc0Verifier.VerifyOptions
        {
            OutDir = string.IsNullOrWhiteSpace(opts.OutDir) ? Path.Combine(Path.GetTempPath(), "dosre-binmc1prove") : opts.OutDir,
            WasmPath = string.IsNullOrWhiteSpace(opts.WasmPath) ? "wasm" : opts.WasmPath,
            WlinkPath = string.IsNullOrWhiteSpace(opts.WlinkPath) ? "wlink" : opts.WlinkPath,
        };
        var verifyRes = Bin16Mc0Verifier.VerifyPromotedAsmBuildsOriginalExe(promotedAsmPath, originalExePath, verifyOpts);

        res.Mc0RebuildByteEqual = verifyRes.ByteEqual;
        res.Mc0RebuildOriginalSha256 = verifyRes.OriginalSha256;
        res.Mc0RebuildRebuiltSha256 = verifyRes.RebuiltSha256;
        res.RebuiltExe = verifyRes.RebuiltExe;
        res.FirstDiff = verifyRes.FirstDiff;
        return res;
    }
}
