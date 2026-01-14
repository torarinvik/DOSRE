using System;
using System.IO;
using System.Linq;
using System.Text;
using SharpDisasm;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Flat 16-bit binary disassembler (COM-like / raw code blobs).
    /// This intentionally does not attempt to infer segments, relocations, or entrypoints.
    /// </summary>
    public static class Bin16Disassembler
    {
        public static bool TryDisassembleToString(
            string inputFile,
            uint origin,
            int? bytesLimit,
            out string output,
            out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (string.IsNullOrWhiteSpace(inputFile) || !File.Exists(inputFile))
            {
                error = "Input file does not exist";
                return false;
            }

            byte[] fileBytes;
            try
            {
                fileBytes = File.ReadAllBytes(inputFile);
            }
            catch (Exception ex)
            {
                error = $"Failed to read input file: {ex.Message}";
                return false;
            }

            if (fileBytes.Length == 0)
            {
                error = "Input file is empty";
                return false;
            }

            var maxBytes = bytesLimit.HasValue ? Math.Max(0, bytesLimit.Value) : fileBytes.Length;
            maxBytes = Math.Min(maxBytes, fileBytes.Length);

            if (maxBytes <= 0)
            {
                error = "No bytes to disassemble";
                return false;
            }

            var code = fileBytes.Take(maxBytes).ToArray();

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (flat 16-bit binary)");
            sb.AppendLine($"; Origin: 0x{origin:X}");
            sb.AppendLine($"; Bytes: 0x{maxBytes:X} ({maxBytes})");
            sb.AppendLine(";");
            sb.AppendLine("; OFFSET BYTES DISASSEMBLY");
            sb.AppendLine(";-------------------------------------------");

            var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_16, origin, true);

            foreach (var ins in dis.Disassemble())
            {
                var addr = (uint)ins.Offset;
                var bytes = ins.Bytes ?? Array.Empty<byte>();
                var bytesHex = string.Concat(bytes.Select(b => b.ToString("X2")));
                sb.AppendLine($"{addr:X8}h {bytesHex,-16} {ins}");
            }

            output = sb.ToString();
            return true;
        }
    }
}
