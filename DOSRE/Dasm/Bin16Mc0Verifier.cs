using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DOSRE.Dasm
{
    public static class Bin16Mc0Verifier
    {
        public sealed class VerifyOptions
        {
            public string WasmPath { get; set; } = "wasm";
            public string WlinkPath { get; set; } = "wlink";

            // wlink system: format dos com (COM-style flat image)
            public string WlinkFormatArgs { get; set; } = "format dos com";

            // If set, verifier writes intermediate files here.
            public string OutDir { get; set; }
        }

        public sealed class VerifyResult
        {
            public bool ByteEqual { get; set; }
            public string OriginalSha256 { get; set; }
            public string RebuiltSha256 { get; set; }
            public long OriginalSize { get; set; }
            public long RebuiltSize { get; set; }
            public string FirstDiff { get; set; }

            public string PromotedAsm { get; set; }
            public string Mc0Text { get; set; }
            public string Mc0Json { get; set; }
            public string ReasmAsm { get; set; }
            public string ObjFile { get; set; }
            public string RebuiltExe { get; set; }
        }

        public static VerifyResult VerifyPromotedAsmBuildsOriginalExe(
            string promotedAsm,
            string originalExe,
            VerifyOptions opts)
        {
            if (string.IsNullOrWhiteSpace(promotedAsm)) throw new ArgumentException("Missing promoted asm", nameof(promotedAsm));
            if (!File.Exists(promotedAsm)) throw new FileNotFoundException("Promoted asm not found", promotedAsm);
            if (string.IsNullOrWhiteSpace(originalExe)) throw new ArgumentException("Missing original exe", nameof(originalExe));
            if (!File.Exists(originalExe)) throw new FileNotFoundException("Original exe not found", originalExe);
            if (opts == null) throw new ArgumentNullException(nameof(opts));

            var outDir = opts.OutDir;
            if (string.IsNullOrWhiteSpace(outDir))
                outDir = Path.Combine(Path.GetTempPath(), "dosre-mc0-verify", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));

            Directory.CreateDirectory(outDir);

            var baseName = Path.GetFileNameWithoutExtension(promotedAsm);
            if (string.IsNullOrWhiteSpace(baseName)) baseName = "mc0";

            var mc0Text = Path.Combine(outDir, baseName + ".mc0");
            var mc0Json = Path.Combine(outDir, baseName + ".mc0.json");
            var reasmAsm = Path.Combine(outDir, baseName + ".mc0.reasm.wasm.asm");
            var objFile = Path.Combine(outDir, baseName + ".mc0.reasm.obj");
            var rebuiltExe = Path.Combine(outDir, baseName + ".mc0.rebuilt.exe");

            // Lift -> MC0 + reasm listing.
            Bin16Mc0.LiftToFiles(promotedAsm, mc0Text, mc0Json, reasmAsm);

            // Assemble (wasm) to OMF obj.
            // Run inside outDir, so use filenames to avoid path duplication issues.
            RunProcess(opts.WasmPath, $"-fo=\"{Path.GetFileName(objFile)}\" \"{Path.GetFileName(reasmAsm)}\"", outDir);

            // Link to DOS COM style image.
            // Use tokenized directives to avoid quoting issues inside wlink.
            // Equivalent to: wlink format dos com name <rebuilt> file <obj> option quiet
            var wlinkArgs = new StringBuilder();
            wlinkArgs.Append(opts.WlinkFormatArgs);
            wlinkArgs.Append(' ');
            wlinkArgs.Append("name ");
            wlinkArgs.Append(EscapeWlinkPath(Path.GetFileName(rebuiltExe)));
            wlinkArgs.Append(' ');
            wlinkArgs.Append("file ");
            wlinkArgs.Append(EscapeWlinkPath(Path.GetFileName(objFile)));
            wlinkArgs.Append(' ');
            wlinkArgs.Append("option quiet");
            RunProcess(opts.WlinkPath, wlinkArgs.ToString(), outDir);

            // Compare bytes.
            var origBytes = File.ReadAllBytes(originalExe);
            var rebBytes = File.ReadAllBytes(rebuiltExe);

            var res = new VerifyResult
            {
                PromotedAsm = promotedAsm,
                Mc0Text = mc0Text,
                Mc0Json = mc0Json,
                ReasmAsm = reasmAsm,
                ObjFile = objFile,
                RebuiltExe = rebuiltExe,
                OriginalSize = origBytes.LongLength,
                RebuiltSize = rebBytes.LongLength,
                OriginalSha256 = Sha256Hex(origBytes),
                RebuiltSha256 = Sha256Hex(rebBytes),
                ByteEqual = origBytes.SequenceEqual(rebBytes),
            };

            if (!res.ByteEqual)
            {
                res.FirstDiff = FindFirstDiff(origBytes, rebBytes);
            }

            return res;
        }

        private static void RunProcess(string fileName, string args, string workingDir)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                WorkingDirectory = workingDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var p = Process.Start(psi);
            if (p == null)
                throw new InvalidOperationException($"Failed to start process: {fileName}");

            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();

            if (p.ExitCode != 0)
            {
                var msg = new StringBuilder();
                msg.AppendLine($"Process failed: {fileName} {args}");
                msg.AppendLine($"ExitCode: {p.ExitCode}");
                if (!string.IsNullOrWhiteSpace(stdout)) msg.AppendLine("STDOUT:\n" + stdout);
                if (!string.IsNullOrWhiteSpace(stderr)) msg.AppendLine("STDERR:\n" + stderr);
                throw new InvalidOperationException(msg.ToString());
            }
        }

        private static string EscapeWlinkPath(string path)
        {
            // wlink directive parsing is a bit special; quoting with double-quotes works, but keep it minimal.
            if (path.Contains(' '))
                return "\"" + path + "\"";
            return path;
        }

        private static string Sha256Hex(byte[] data)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
        }

        private static string FindFirstDiff(byte[] a, byte[] b)
        {
            var n = Math.Min(a.Length, b.Length);
            for (var i = 0; i < n; i++)
            {
                if (a[i] != b[i])
                    return $"offset=0x{i:X} a=0x{a[i]:X2} b=0x{b[i]:X2}";
            }

            if (a.Length != b.Length)
                return $"length differs: a={a.Length} b={b.Length}";

            return "unknown";
        }
    }
}
