using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Lifts the "byte-authoritative" promoted BIN16/WASM-style assembly back into a 1:1 structured form
    /// (a crude C-like AST) that can be emitted as JSON and as compilable C.
    ///
    /// Goal: a provable 1:1 relationship between the assembly listing and the emitted representation:
    /// - Every line with an address+hexbytes comment becomes a LiftNode with the exact same addr+bytes.
    /// - Output includes SHA-256 over the lifted stream (addr+bytes) so consumers can validate integrity.
    ///
    /// This is intentionally low-level: it preserves bytes; it does not attempt high-level decompilation.
    /// </summary>
    public static class Bin16AsmLifter
    {
        public sealed class LiftFile
        {
            [JsonPropertyName("source")]
            public string Source { get; set; }

            [JsonPropertyName("generatedUtc")]
            public string GeneratedUtc { get; set; }

            [JsonPropertyName("streamSha256")]
            public string StreamSha256 { get; set; }

            [JsonPropertyName("nodes")]
            public List<LiftNode> Nodes { get; set; } = new();
        }

        public sealed class LiftNode
        {
            [JsonPropertyName("index")]
            public int Index { get; set; }

            [JsonPropertyName("kind")]
            public string Kind { get; set; } // "insn" | "db" | "other"

            [JsonPropertyName("labels")]
            public List<string> Labels { get; set; } = new();

            [JsonPropertyName("addr")]
            public uint? Addr { get; set; }

            [JsonPropertyName("bytesHex")]
            public string BytesHex { get; set; }

            [JsonPropertyName("asm")]
            public string Asm { get; set; }

            [JsonPropertyName("sourceLine")]
            public string SourceLine { get; set; }
        }

        private static readonly Regex LabelOnly = new Regex(
            @"^\s*(?<label>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)\s*:\s*(?:;.*)?$",
            RegexOptions.Compiled);

        // Matches the byte-authoritative comment appended by DOSRE/BIN16 tooling:
        // "; 000001A4h B8003D  mov ax, 0x3D00"
        private static readonly Regex AddrBytesAsmComment = new Regex(
            @";\s*(?<addr>[0-9A-Fa-f]{1,8})h\s+(?<hex>[0-9A-Fa-f]{2,})\s+(?<asm>.+?)\s*$",
            RegexOptions.Compiled);

        public static void LiftToFiles(string inAsm, string outJson, string outC, string outH)
        {
            if (string.IsNullOrWhiteSpace(inAsm)) throw new ArgumentException("Missing input asm", nameof(inAsm));
            if (!File.Exists(inAsm)) throw new FileNotFoundException("Input asm not found", inAsm);

            var lines = File.ReadAllLines(inAsm);
            var lifted = LiftLines(lines, inAsm);

            if (!string.IsNullOrWhiteSpace(outJson))
            {
                var opts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                };
                File.WriteAllText(outJson, JsonSerializer.Serialize(lifted, opts));
            }

            if (!string.IsNullOrWhiteSpace(outH))
            {
                File.WriteAllText(outH, RenderHeader(lifted));
            }

            if (!string.IsNullOrWhiteSpace(outC))
            {
                File.WriteAllText(outC, RenderC(lifted, outH));
            }
        }

        public static LiftFile LiftLines(IReadOnlyList<string> lines, string sourceName = null)
        {
            var file = new LiftFile
            {
                Source = sourceName ?? string.Empty,
                GeneratedUtc = DateTime.UtcNow.ToString("O")
            };

            // Accumulate labels that apply to the next lifted node.
            var pendingLabels = new List<string>();

            var streamHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            for (var i = 0; i < lines.Count; i++)
            {
                var line = lines[i] ?? string.Empty;

                var mLabel = LabelOnly.Match(line);
                if (mLabel.Success)
                {
                    var lbl = mLabel.Groups["label"].Value;
                    if (!string.IsNullOrWhiteSpace(lbl))
                        pendingLabels.Add(lbl);
                    continue;
                }

                var node = new LiftNode
                {
                    Index = file.Nodes.Count,
                    SourceLine = line,
                    Labels = pendingLabels.Count == 0 ? new List<string>() : new List<string>(pendingLabels)
                };
                pendingLabels.Clear();

                var semi = line.IndexOf(';');
                if (semi >= 0)
                {
                    var comment = line.Substring(semi);
                    var m = AddrBytesAsmComment.Match(comment);
                    if (m.Success)
                    {
                        var addrHex = m.Groups["addr"].Value;
                        var bytesHex = m.Groups["hex"].Value;
                        var asm = m.Groups["asm"].Value.Trim();

                        // Parse addr
                        if (!uint.TryParse(addrHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var addr))
                            throw new InvalidDataException($"Bad address token '{addrHex}' on line {i + 1}");

                        bytesHex = NormalizeHex(bytesHex);
                        if (bytesHex.Length % 2 != 0)
                            throw new InvalidDataException($"Odd-length byte hex '{bytesHex}' on line {i + 1}");

                        node.Addr = addr;
                        node.BytesHex = bytesHex;
                        node.Asm = asm;

                        var trimmed = line.TrimStart();
                        node.Kind = trimmed.StartsWith("db ", StringComparison.OrdinalIgnoreCase) ? "db" : "insn";

                        // Update hash: addr (LE) + raw bytes.
                        Span<byte> ab = stackalloc byte[4];
                        ab[0] = (byte)(addr & 0xFF);
                        ab[1] = (byte)((addr >> 8) & 0xFF);
                        ab[2] = (byte)((addr >> 16) & 0xFF);
                        ab[3] = (byte)((addr >> 24) & 0xFF);
                        streamHash.AppendData(ab);
                        streamHash.AppendData(ParseHex(bytesHex));

                        file.Nodes.Add(node);
                        continue;
                    }
                }

                // Not a lifted byte-authoritative line; keep it as 'other' for context.
                node.Kind = "other";
                file.Nodes.Add(node);
            }

            file.StreamSha256 = Convert.ToHexString(streamHash.GetHashAndReset()).ToLowerInvariant();
            return file;
        }

        private static string NormalizeHex(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return string.Empty;
            var sb = new StringBuilder(hex.Length);
            foreach (var c in hex)
            {
                if (Uri.IsHexDigit(c)) sb.Append(char.ToUpperInvariant(c));
            }
            return sb.ToString();
        }

        private static byte[] ParseHex(string hex)
        {
            hex = NormalizeHex(hex);
            var n = hex.Length / 2;
            var b = new byte[n];
            for (var i = 0; i < n; i++)
            {
                var tok = hex.Substring(i * 2, 2);
                b[i] = byte.Parse(tok, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }
            return b;
        }

        private static string RenderHeader(LiftFile lf)
        {
            var sb = new StringBuilder();
            sb.AppendLine("#pragma once");
            sb.AppendLine("#include <stdint.h>");
            sb.AppendLine("#include <stddef.h>");
            sb.AppendLine();
            sb.AppendLine("// Generated by DOSRE Bin16AsmLifter");
            sb.AppendLine($"// stream_sha256: {lf.StreamSha256}");
            sb.AppendLine();
            sb.AppendLine("typedef struct CrudeIns {");
            sb.AppendLine("    uint32_t addr;   // logical address from listing comment");
            sb.AppendLine("    size_t   len;");
            sb.AppendLine("    const uint8_t *bytes; // points at a generated byte blob");
            sb.AppendLine("    const char *asm_text; // mnemonic+operands (for humans)");
            sb.AppendLine("} CrudeIns;");
            sb.AppendLine();
            sb.AppendLine("extern const CrudeIns g_crude_program[];");
            sb.AppendLine("extern const uint32_t g_crude_program_count;");
            return sb.ToString();
        }

        private static string RenderC(LiftFile lf, string outH)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Generated by DOSRE Bin16AsmLifter");
            sb.AppendLine($"// source: {lf.Source}");
            sb.AppendLine($"// stream_sha256: {lf.StreamSha256}");
            sb.AppendLine();

            if (!string.IsNullOrWhiteSpace(outH))
            {
                var hName = Path.GetFileName(outH);
                sb.AppendLine($"#include \"{hName}\"");
            }
            else
            {
                sb.AppendLine("#include <stdint.h>");
                sb.AppendLine("#include <stddef.h>");
                sb.AppendLine("typedef struct CrudeIns { uint32_t addr; size_t len; const uint8_t *bytes; const char *asm_text; } CrudeIns;");
            }

            sb.AppendLine();

            // Emit byte blobs for each lifted node.
            var liftedNodes = lf.Nodes.Where(x => x.Kind == "insn" || x.Kind == "db").ToList();
            for (var i = 0; i < liftedNodes.Count; i++)
            {
                var n = liftedNodes[i];
                if (!n.Addr.HasValue || string.IsNullOrWhiteSpace(n.BytesHex))
                    continue;
                var bytes = ParseHex(n.BytesHex);
                var byteInit = string.Join(", ", bytes.Select(b => $"0x{b:X2}"));
                sb.AppendLine($"static const uint8_t g_crude_blob_{i:D6}[] = {{ {byteInit} }};");
            }

            sb.AppendLine();
            sb.AppendLine("const CrudeIns g_crude_program[] = {");

            for (var i = 0; i < liftedNodes.Count; i++)
            {
                var n = liftedNodes[i];
                if (!n.Addr.HasValue || string.IsNullOrWhiteSpace(n.BytesHex))
                    continue;

                var bytes = ParseHex(n.BytesHex);
                var asmText = (n.Asm ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");
                sb.AppendLine($"    {{ 0x{n.Addr.Value:X8}u, sizeof(g_crude_blob_{i:D6}), g_crude_blob_{i:D6}, \"{asmText}\" }},");
            }

            sb.AppendLine("};");
            sb.AppendLine("const uint32_t g_crude_program_count = (uint32_t)(sizeof(g_crude_program)/sizeof(g_crude_program[0]));");
            return sb.ToString();
        }
    }
}
