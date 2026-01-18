using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace DOSRE.Dasm;

public static class Bin16Mc0Builder
{
    public sealed class BuildOptions
    {
        public string WasmPath { get; set; } = "wasm";
        public string WlinkPath { get; set; } = "wlink";

        // Examples:
        // - "format dos com"
        // - "format raw bin"
        public string WlinkFormatArgs { get; set; } = "format dos com";

        public string OutDir { get; set; }

        public bool AllowTemplateByteMismatch { get; set; }

        // Output filename (relative to OutDir). If empty, defaults to <templateBase>.mc0.built.bin
        public string OutputName { get; set; }
    }

    public sealed class BuildResult
    {
        public string OutDir { get; set; }
        public string ReasmAsm { get; set; }
        public string ObjFile { get; set; }
        public string BuiltBinary { get; set; }
    }

    public static BuildResult BuildFromMc0AndPromotedTemplate(string promotedAsmTemplate, Bin16Mc0.Mc0File mc0, BuildOptions opts)
    {
        if (string.IsNullOrWhiteSpace(promotedAsmTemplate)) throw new ArgumentException("promotedAsmTemplate is required", nameof(promotedAsmTemplate));
        if (!File.Exists(promotedAsmTemplate)) throw new FileNotFoundException("Promoted asm template not found", promotedAsmTemplate);
        if (mc0 == null) throw new ArgumentNullException(nameof(mc0));
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        var outDir = string.IsNullOrWhiteSpace(opts.OutDir)
            ? Path.Combine(Path.GetTempPath(), "dosre-mc0-build", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture))
            : opts.OutDir;
        Directory.CreateDirectory(outDir);

        var baseName = Path.GetFileNameWithoutExtension(promotedAsmTemplate);
        if (string.IsNullOrWhiteSpace(baseName)) baseName = "mc0";

        var reasmAsm = Path.Combine(outDir, baseName + ".mc0.build.reasm.wasm.asm");
        var objFile = Path.Combine(outDir, baseName + ".mc0.build.reasm.obj");

        var outName = string.IsNullOrWhiteSpace(opts.OutputName)
            ? baseName + ".mc0.built.bin"
            : opts.OutputName;
        var builtBinary = Path.Combine(outDir, outName);

        var asmText = Bin16Mc0.RenderDbAsmFromPromotedTemplate(promotedAsmTemplate, mc0, allowByteMismatch: opts.AllowTemplateByteMismatch);
        File.WriteAllText(reasmAsm, asmText);

        RunProcess(opts.WasmPath, $"-zq -fo=\"{Path.GetFileName(objFile)}\" \"{Path.GetFileName(reasmAsm)}\"", outDir);

        // Equivalent to: wlink <format> name <out> file <obj> option quiet
        var wlinkArgs = new StringBuilder();
        wlinkArgs.Append(string.IsNullOrWhiteSpace(opts.WlinkFormatArgs) ? "format dos com" : opts.WlinkFormatArgs);
        wlinkArgs.Append(' ');
        wlinkArgs.Append("name ");
        wlinkArgs.Append(EscapeWlinkPath(Path.GetFileName(builtBinary)));
        wlinkArgs.Append(' ');
        wlinkArgs.Append("file ");
        wlinkArgs.Append(EscapeWlinkPath(Path.GetFileName(objFile)));
        wlinkArgs.Append(' ');
        wlinkArgs.Append("option quiet");

        RunProcess(opts.WlinkPath, wlinkArgs.ToString(), outDir);

        return new BuildResult
        {
            OutDir = outDir,
            ReasmAsm = reasmAsm,
            ObjFile = objFile,
            BuiltBinary = builtBinary,
        };
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
        if (path.Contains(' '))
            return "\"" + path + "\"";
        return path;
    }
}
