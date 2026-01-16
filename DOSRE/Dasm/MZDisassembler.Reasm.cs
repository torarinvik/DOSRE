using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
        private enum EnumReasmDialect
        {
            Nasm,
            WasmMasm,
        }

        public sealed class MzRelocation
        {
            public ushort offset { get; set; }
            public ushort segment { get; set; }
        }

        public sealed class MzReasmExport
        {
            public string input { get; set; }
            public int fileLength { get; set; }
            public int headerDeclaredFileLength { get; set; }

            public ushort e_cblp { get; set; }
            public ushort e_cp { get; set; }
            public ushort e_crlc { get; set; }
            public ushort e_cparhdr { get; set; }
            public ushort e_minalloc { get; set; }
            public ushort e_maxalloc { get; set; }
            public ushort e_ss { get; set; }
            public ushort e_sp { get; set; }
            public ushort e_ip { get; set; }
            public ushort e_cs { get; set; }
            public ushort e_lfarlc { get; set; }
            public ushort e_ovno { get; set; }
            public uint e_lfanew { get; set; }

            public int headerSizeBytes { get; set; }
            public int relocTableOffset { get; set; }
            public int relocCount { get; set; }

            public List<MzRelocation> relocations { get; set; }
        }

        public static bool TryExportReassembly(
            string inputFile,
            string outAsmFile,
            string outJsonFile,
            out string error)
        {
            return TryExportReassembly(inputFile, outAsmFile, outJsonFile, wasmCompat: false, out error);
        }

        public static bool TryExportReassembly(
            string inputFile,
            string outAsmFile,
            string outJsonFile,
            bool wasmCompat,
            out string error)
        {
            error = string.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(inputFile) || !File.Exists(inputFile))
                {
                    error = "Input file does not exist";
                    return false;
                }

                if (string.IsNullOrWhiteSpace(outAsmFile) && string.IsNullOrWhiteSpace(outJsonFile))
                {
                    error = "Please specify at least one output: -MZREASM <out.asm> and/or -MZREASMJSON <out.json>";
                    return false;
                }

                var fileBytes = File.ReadAllBytes(inputFile);
                if (!TryParseMZHeader(fileBytes, out var h))
                {
                    error = "MZ header not found";
                    return false;
                }

                var declaredSize = ComputeMzFileSizeBytes(h, fileBytes.Length);
                var headerSizeBytes = h.e_cparhdr * 16;

                var relocOff = h.e_lfarlc;
                var relocCount = h.e_crlc;

                var relocations = new List<MzRelocation>();
                var relocTableLen = (int)relocCount * 4;
                var relocTableEnd = relocOff + relocTableLen;
                if (relocOff > 0 && relocCount > 0 && relocTableEnd <= fileBytes.Length)
                {
                    for (var i = 0; i < relocCount; i++)
                    {
                        var entryOff = relocOff + i * 4;
                        relocations.Add(new MzRelocation
                        {
                            offset = ReadUInt16(fileBytes, entryOff + 0),
                            segment = ReadUInt16(fileBytes, entryOff + 2)
                        });
                    }
                }

                if (!string.IsNullOrWhiteSpace(outJsonFile))
                {
                    var payload = new MzReasmExport
                    {
                        input = inputFile,
                        fileLength = fileBytes.Length,
                        headerDeclaredFileLength = declaredSize,

                        e_cblp = h.e_cblp,
                        e_cp = h.e_cp,
                        e_crlc = h.e_crlc,
                        e_cparhdr = h.e_cparhdr,
                        e_minalloc = h.e_minalloc,
                        e_maxalloc = h.e_maxalloc,
                        e_ss = h.e_ss,
                        e_sp = h.e_sp,
                        e_ip = h.e_ip,
                        e_cs = h.e_cs,
                        e_lfarlc = h.e_lfarlc,
                        e_ovno = h.e_ovno,
                        e_lfanew = h.e_lfanew,

                        headerSizeBytes = headerSizeBytes,
                        relocTableOffset = relocOff,
                        relocCount = relocCount,
                        relocations = relocations
                    };

                    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outJsonFile)) ?? ".");
                    var opts = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                    };
                    File.WriteAllText(outJsonFile, JsonSerializer.Serialize(payload, opts));
                }

                if (!string.IsNullOrWhiteSpace(outAsmFile))
                {
                    var asm = BuildReasmAsm(inputFile, fileBytes, h, declaredSize, headerSizeBytes, relocations,
                        wasmCompat ? EnumReasmDialect.WasmMasm : EnumReasmDialect.Nasm);
                    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outAsmFile)) ?? ".");
                    File.WriteAllText(outAsmFile, asm);
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static string BuildReasmAsm(
            string inputFile,
            byte[] fileBytes,
            MZHeader h,
            int declaredSize,
            int headerSizeBytes,
            List<MzRelocation> relocations,
            EnumReasmDialect dialect)
        {
            var sb = new StringBuilder();
            sb.AppendLine(dialect == EnumReasmDialect.WasmMasm
                ? "; MZ reassembly export (byte-perfect; OpenWatcom WASM/MASM-compatible syntax)"
                : "; MZ reassembly export (byte-perfect via NASM -f bin)");
            sb.AppendLine($"; Input: {Path.GetFileName(inputFile)}");
            sb.AppendLine($"; File length: {fileBytes.Length} bytes");
            if (declaredSize != fileBytes.Length)
                sb.AppendLine($"; Header-declared file length: {declaredSize} bytes (differs from actual)");
            sb.AppendLine($"; Entry CS:IP {h.e_cs:X4}:{h.e_ip:X4}");
            sb.AppendLine($"; SS:SP {h.e_ss:X4}:{h.e_sp:X4}");
            sb.AppendLine($"; Header paragraphs: {h.e_cparhdr} (0x{headerSizeBytes:X} bytes)");
            sb.AppendLine($"; Reloc table: off=0x{h.e_lfarlc:X} count={h.e_crlc}");
            sb.AppendLine($";");
            if (dialect == EnumReasmDialect.WasmMasm)
            {
                sb.AppendLine("; Build (OpenWatcom):");
                sb.AppendLine(";   wasm source.asm -fo=out.obj");
                sb.AppendLine(";   wlink format raw bin name out.exe file out.obj");
                sb.AppendLine(";");
                sb.AppendLine(".8086");
                sb.AppendLine(".model tiny");
                sb.AppendLine(".code");
                sb.AppendLine("org 0");
            }
            else
            {
                sb.AppendLine("bits 16");
                sb.AppendLine("org 0");
            }
            sb.AppendLine("mz_file:");

            var relocOff = Math.Max(0, (int)h.e_lfarlc);
            var relocTableLen = Math.Max(0, (int)h.e_crlc * 4);

            var beforeEnd = Math.Min(relocOff, fileBytes.Length);
            var relocStart = beforeEnd;
            var relocEndExpected = relocOff + relocTableLen;
            var relocEndClamped = Math.Min(fileBytes.Length, Math.Max(relocStart, relocEndExpected));

            // Emit bytes before relocation table.
            EmitDbBytes(sb, fileBytes, 0, beforeEnd, dialect);

            // Emit relocation table region.
            if (relocTableLen > 0 && relocStart < relocEndClamped)
            {
                sb.AppendLine();

                var canDecodeRelocs = h.e_crlc > 0 && relocOff >= 0 && relocEndExpected <= fileBytes.Length &&
                                      relocations != null && relocations.Count == h.e_crlc;

                if (canDecodeRelocs)
                {
                    sb.AppendLine("mz_relocs:");
                    sb.AppendLine($"; Relocation entries (offset, segment) ; count={h.e_crlc}");
                    for (var i = 0; i < relocations.Count; i++)
                    {
                        var r = relocations[i];
                        if (dialect == EnumReasmDialect.WasmMasm)
                            sb.AppendLine($"dw {ToMasmHexU32(r.offset, 4)}, {ToMasmHexU32(r.segment, 4)} ; reloc[{i}] off=0x{r.offset:X4} seg=0x{r.segment:X4}");
                        else
                            sb.AppendLine($"dw 0x{r.offset:X4}, 0x{r.segment:X4} ; reloc[{i}] off=0x{r.offset:X4} seg=0x{r.segment:X4}");
                    }
                }
                else
                {
                    sb.AppendLine("mz_relocs_bytes:");
                    sb.AppendLine($"; Relocation table bytes (could not decode safely) ; expectedLen={relocTableLen} actualLen={relocEndClamped - relocStart}");
                    EmitDbBytes(sb, fileBytes, relocStart, relocEndClamped, dialect);
                }
            }

            // Emit bytes after relocation table.
            var tailStart = relocEndClamped;
            if (tailStart < fileBytes.Length)
            {
                sb.AppendLine();
                sb.AppendLine("mz_tail:");
                EmitDbBytes(sb, fileBytes, tailStart, fileBytes.Length, dialect);
            }

            if (dialect == EnumReasmDialect.WasmMasm)
            {
                sb.AppendLine();
                sb.AppendLine("end");
            }

            return sb.ToString();
        }

        private static string ToMasmHexU32(uint value, int minDigits)
        {
            if (value == 0)
                return "0";

            var hex = value.ToString("X");
            if (minDigits > 0)
                hex = hex.PadLeft(minDigits, '0');

            // MASM requires a leading 0 if the first digit is A-F.
            var c0 = hex[0];
            if (c0 >= 'A' && c0 <= 'F')
                hex = "0" + hex;

            return hex + "h";
        }

        private static void EmitDbBytes(StringBuilder sb, byte[] bytes, int start, int endExclusive, EnumReasmDialect dialect)
        {
            if (bytes == null || sb == null)
                return;

            start = Math.Max(0, start);
            endExclusive = Math.Min(bytes.Length, endExclusive);
            if (start >= endExclusive)
                return;

            const int perLine = 16;
            for (var i = start; i < endExclusive; i += perLine)
            {
                var chunkEnd = Math.Min(endExclusive, i + perLine);
                var parts = new List<string>(perLine);
                for (var j = i; j < chunkEnd; j++)
                {
                    if (dialect == EnumReasmDialect.WasmMasm)
                        parts.Add(ToMasmHexU32(bytes[j], 2));
                    else
                        parts.Add($"0x{bytes[j]:X2}");
                }

                sb.Append("db ");
                sb.AppendLine(string.Join(", ", parts));
            }
        }
    }
}
