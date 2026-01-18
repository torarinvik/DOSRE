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
    /// MC0 (Machine-C Level 0) is a deterministic, C-shaped, byte-faithful layer on top of BIN16 promoted asm.
    ///
    /// Contract (today):
    /// - Every MC0 statement carries an origin (addr + exact bytes) and round-trips back to identical bytes.
    /// - The textual MC0 format is deterministic and parseable, enabling mechanical edits later.
    ///
    /// This intentionally starts small: it pretty-prints a subset of common mnemonics to canonical MC0, but
    /// always preserves origin bytes so the verifier can be strict even for unknown instructions.
    /// </summary>
    public static class Bin16Mc0
    {
        public sealed class Mc0File
        {
            [JsonPropertyName("source")]
            public string Source { get; set; }

            [JsonPropertyName("generatedUtc")]
            public string GeneratedUtc { get; set; }

            [JsonPropertyName("streamSha256")]
            public string StreamSha256 { get; set; }

            [JsonPropertyName("statements")]
            public List<Mc0Stmt> Statements { get; set; } = new();
        }

        public sealed class Mc0Stmt
        {
            [JsonPropertyName("index")]
            public int Index { get; set; }

            [JsonPropertyName("labels")]
            public List<string> Labels { get; set; } = new();

            [JsonPropertyName("addr")]
            public uint Addr { get; set; }

            [JsonPropertyName("bytesHex")]
            public string BytesHex { get; set; }

            [JsonPropertyName("asm")]
            public string Asm { get; set; }

            [JsonPropertyName("mc0")]
            public string Mc0 { get; set; }
        }

        private static readonly Regex LabelOnly = new Regex(
            @"^\s*(?:}\s*)*(?<label>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)\s*:\s*(?://.*)?$",
            RegexOptions.Compiled);

        private static readonly Regex OriginComment = new Regex(
            @"@(?<addr>[0-9A-Fa-f]{1,8})\s+(?<hex>[0-9A-Fa-f]{2,})",
            RegexOptions.Compiled);

        public static void LiftToFiles(string inPromotedAsm, string outMc0, string outJson, string outReasmAsm)
        {
            if (string.IsNullOrWhiteSpace(inPromotedAsm)) throw new ArgumentException("Missing input asm", nameof(inPromotedAsm));
            if (!File.Exists(inPromotedAsm)) throw new FileNotFoundException("Input asm not found", inPromotedAsm);

            var mc0 = LiftPromotedAsmToMc0(inPromotedAsm);

            if (!string.IsNullOrWhiteSpace(outJson))
            {
                var opts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                };
                File.WriteAllText(outJson, JsonSerializer.Serialize(mc0, opts));
            }

            if (!string.IsNullOrWhiteSpace(outMc0))
            {
                var txt = RenderMc0Text(mc0);
                File.WriteAllText(outMc0, txt);

                // Deterministic roundtrip check for the emitted text format.
                var parsed = ParseMc0Text(File.ReadAllLines(outMc0), sourceName: outMc0);
                VerifyByteIdentity(mc0, parsed);
            }

            if (!string.IsNullOrWhiteSpace(outReasmAsm))
            {
                // For assembly/linking, preserve the original promoted listing structure (segments/org/end/etc)
                // and replace each byte-authoritative line with an unambiguous db list.
                File.WriteAllText(outReasmAsm, RenderDbAsmFromPromotedTemplate(inPromotedAsm, mc0));
            }
        }

        public static Mc0File LiftPromotedAsmToMc0(string inPromotedAsm)
        {
            var lifted = Bin16AsmLifter.LiftLines(File.ReadAllLines(inPromotedAsm), inPromotedAsm);
            var nodes = lifted.Nodes
                .Where(n => (n.Kind == "insn" || n.Kind == "db") && n.Addr.HasValue && !string.IsNullOrWhiteSpace(n.BytesHex))
                .ToList();

            var file = new Mc0File
            {
                Source = inPromotedAsm,
                GeneratedUtc = DateTime.UtcNow.ToString("O"),
                StreamSha256 = lifted.StreamSha256,
            };

            for (var i = 0; i < nodes.Count; i++)
            {
                var n = nodes[i];
                var bytesHex = NormalizeHex(n.BytesHex);
                var stmtText = TranslateAsmToMc0(n.Asm ?? string.Empty, bytesHex);

                file.Statements.Add(new Mc0Stmt
                {
                    Index = file.Statements.Count,
                    Labels = n.Labels?.Count > 0 ? new List<string>(n.Labels) : new List<string>(),
                    Addr = n.Addr!.Value,
                    BytesHex = bytesHex,
                    Asm = n.Asm ?? string.Empty,
                    Mc0 = stmtText,
                });
            }

            // Prefer the original stream hash, but ensure our view is consistent.
            file.StreamSha256 = ComputeStreamSha256(file.Statements);
            return file;
        }

        public static string RenderMc0Text(Mc0File file)
        {
            if (file == null) throw new ArgumentNullException(nameof(file));

            var sb = new StringBuilder();
            sb.AppendLine("// MC0 (Machine-C Level 0) generated by DOSRE");
            sb.AppendLine($"// source: {file.Source}");
            sb.AppendLine($"// stream_sha256: {file.StreamSha256}");
            sb.AppendLine("// format: <stmt>; // @AAAAAAAA HEXBYTES ; original asm");
            sb.AppendLine();

            foreach (var st in file.Statements)
            {
                if (st.Labels != null)
                {
                    foreach (var lbl in st.Labels)
                    {
                        if (!string.IsNullOrWhiteSpace(lbl))
                            sb.AppendLine($"{lbl}:");
                    }
                }

                var stmt = (st.Mc0 ?? string.Empty).Trim();
                if (stmt.EndsWith(";", StringComparison.Ordinal))
                    stmt = stmt.Substring(0, stmt.Length - 1).TrimEnd();

                sb.Append("    ");
                sb.Append(stmt);
                sb.Append("; // @");
                sb.Append(st.Addr.ToString("X8"));
                sb.Append(' ');
                sb.Append(NormalizeHex(st.BytesHex));
                sb.Append(" ; ");
                sb.AppendLine(st.Asm ?? string.Empty);
            }

            return sb.ToString();
        }

        public static Mc0File ParseMc0Text(IReadOnlyList<string> lines, string sourceName = null)
        {
            if (lines == null) throw new ArgumentNullException(nameof(lines));

            var file = new Mc0File
            {
                Source = sourceName ?? string.Empty,
                GeneratedUtc = DateTime.UtcNow.ToString("O"),
            };

            var pendingLabels = new List<string>();

            for (var i = 0; i < lines.Count; i++)
            {
                var line = lines[i] ?? string.Empty;
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    continue;
                if (trimmed.StartsWith("//", StringComparison.Ordinal))
                    continue;

                var mLabel = LabelOnly.Match(line);
                if (mLabel.Success)
                {
                    var lbl = mLabel.Groups["label"].Value;
                    if (!string.IsNullOrWhiteSpace(lbl))
                        pendingLabels.Add(lbl);
                    continue;
                }

                // Split stmt vs comment
                var stmtPart = line;
                var commentPart = string.Empty;
                var idx = line.IndexOf("//", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    stmtPart = line.Substring(0, idx);
                    commentPart = line.Substring(idx + 2);
                }

                var stmtText = stmtPart.Trim();
                if (stmtText.EndsWith(";", StringComparison.Ordinal))
                    stmtText = stmtText.Substring(0, stmtText.Length - 1).TrimEnd();

                if (string.IsNullOrWhiteSpace(stmtText))
                    continue;

                var mOrigin = OriginComment.Match(commentPart);
                if (!mOrigin.Success)
                    throw new InvalidDataException($"MC0 missing origin tag on line {i + 1} (expected // @AAAAAAAA HEX...) ");

                var addrHex = mOrigin.Groups["addr"].Value;
                var bytesHex = NormalizeHex(mOrigin.Groups["hex"].Value);

                if (!uint.TryParse(addrHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var addr))
                    throw new InvalidDataException($"Bad origin addr '{addrHex}' on line {i + 1}");

                if (bytesHex.Length % 2 != 0)
                    throw new InvalidDataException($"Odd-length origin bytes '{bytesHex}' on line {i + 1}");

                file.Statements.Add(new Mc0Stmt
                {
                    Index = file.Statements.Count,
                    Labels = pendingLabels.Count == 0 ? new List<string>() : new List<string>(pendingLabels),
                    Addr = addr,
                    BytesHex = bytesHex,
                    Asm = string.Empty,
                    Mc0 = stmtText,
                });

                pendingLabels.Clear();
            }

            file.StreamSha256 = ComputeStreamSha256(file.Statements);
            return file;
        }

        public static void VerifyByteIdentity(Mc0File expected, Mc0File actual)
        {
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (actual == null) throw new ArgumentNullException(nameof(actual));

            if (expected.Statements.Count != actual.Statements.Count)
                throw new InvalidDataException($"MC0 roundtrip changed statement count: {expected.Statements.Count} -> {actual.Statements.Count}");

            for (var i = 0; i < expected.Statements.Count; i++)
            {
                var a = expected.Statements[i];
                var b = actual.Statements[i];

                if (a.Addr != b.Addr)
                    throw new InvalidDataException($"MC0 roundtrip changed addr at index {i}: 0x{a.Addr:X8} -> 0x{b.Addr:X8}");

                var ax = NormalizeHex(a.BytesHex);
                var bx = NormalizeHex(b.BytesHex);
                if (!string.Equals(ax, bx, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"MC0 roundtrip changed bytes at index {i}: {ax} -> {bx}");
            }

            var ha = ComputeStreamSha256(expected.Statements);
            var hb = ComputeStreamSha256(actual.Statements);
            if (!string.Equals(ha, hb, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"MC0 roundtrip changed stream hash: {ha} -> {hb}");
        }

        public static string RenderDbAsm(Mc0File file)
        {
            if (file == null) throw new ArgumentNullException(nameof(file));

            var sb = new StringBuilder();
            sb.AppendLine("; Re-emitted from MC0 by DOSRE (byte-faithful)");
            sb.AppendLine($"; stream_sha256: {file.StreamSha256}");
            sb.AppendLine();

            foreach (var st in file.Statements)
            {
                if (st.Labels != null)
                {
                    foreach (var lbl in st.Labels)
                    {
                        if (!string.IsNullOrWhiteSpace(lbl))
                            sb.AppendLine($"{lbl}:");
                    }
                }

                var bytes = ParseHex(st.BytesHex);
                sb.Append("    db ");
                for (var i = 0; i < bytes.Length; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(bytes[i].ToString("X2"));
                    sb.Append("h");
                }

                sb.Append(" ; ");
                sb.Append(st.Addr.ToString("X8"));
                sb.Append("h ");
                sb.Append(NormalizeHex(st.BytesHex));

                var asm = (st.Asm ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(asm))
                {
                    sb.Append("  ");
                    sb.Append(asm);
                }

                var mc0 = (st.Mc0 ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(mc0))
                {
                    sb.Append("  | mc0: ");
                    sb.Append(mc0);
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }

        // Matches the byte-authoritative comment appended by DOSRE/BIN16 tooling:
        // "; 000001A4h B8003D  mov ax, 0x3D00"
        private static readonly Regex AddrBytesAsmComment = new Regex(
            @";\s*(?<addr>[0-9A-Fa-f]{1,8})h\s+(?<hex>[0-9A-Fa-f]{2,})\s+(?<asm>.+?)\s*$",
            RegexOptions.Compiled);

        public static string RenderDbAsmFromPromotedTemplate(string inPromotedAsm, Mc0File file)
        {
            if (string.IsNullOrWhiteSpace(inPromotedAsm)) throw new ArgumentException("Missing input asm", nameof(inPromotedAsm));
            if (!File.Exists(inPromotedAsm)) throw new FileNotFoundException("Input asm not found", inPromotedAsm);
            if (file == null) throw new ArgumentNullException(nameof(file));

            var bytesByAddr = file.Statements.ToDictionary(s => s.Addr, s => NormalizeHex(s.BytesHex));

            var lines = File.ReadAllLines(inPromotedAsm);
            var sb = new StringBuilder();

            sb.AppendLine("; Re-emitted from MC0 by DOSRE (byte-faithful, template-preserving)");
            sb.AppendLine($"; source: {inPromotedAsm}");
            sb.AppendLine($"; stream_sha256: {file.StreamSha256}");
            sb.AppendLine();

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i] ?? string.Empty;
                var semi = line.IndexOf(';');
                if (semi >= 0)
                {
                    var comment = line.Substring(semi);
                    var m = AddrBytesAsmComment.Match(comment);
                    if (m.Success)
                    {
                        var addrHex = m.Groups["addr"].Value;
                        var bytesHex = NormalizeHex(m.Groups["hex"].Value);

                        if (!uint.TryParse(addrHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var addr))
                            throw new InvalidDataException($"Bad address token '{addrHex}' in template on line {i + 1}");

                        if (!bytesByAddr.TryGetValue(addr, out var fromMc0))
                            throw new InvalidDataException($"Template references addr 0x{addr:X8} not present in MC0 statements (line {i + 1})");

                        if (!string.Equals(fromMc0, bytesHex, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException($"Template bytes mismatch at 0x{addr:X8}: template={bytesHex} mc0={fromMc0}");

                        var code = line.Substring(0, semi);
                        var leading = new string(code.TakeWhile(char.IsWhiteSpace).ToArray());
                        var rest = code.TrimStart();

                        // Preserve an inline label prefix if present (e.g., "loc_1234:").
                        string labelPrefix = null;
                        var colonIdx = rest.IndexOf(':');
                        if (colonIdx >= 0)
                        {
                            // Only treat it as a label if it matches identifier syntax.
                            var candidate = rest.Substring(0, colonIdx).Trim();
                            if (LabelOnly.IsMatch(candidate + ":"))
                                labelPrefix = candidate + ":";
                        }

                        var bytes = ParseHex(fromMc0);

                        sb.Append(leading);
                        if (!string.IsNullOrWhiteSpace(labelPrefix))
                        {
                            sb.Append(labelPrefix);
                            sb.Append(' ');
                        }
                        sb.Append("db ");
                        for (var bi = 0; bi < bytes.Length; bi++)
                        {
                            if (bi > 0) sb.Append(',');
                            sb.Append(FormatByteWasm(bytes[bi]));
                        }

                        // Keep the original byte-authoritative comment for audit/debug.
                        sb.Append(' ');
                        sb.AppendLine(comment);
                        continue;
                    }
                }

                sb.AppendLine(line);
            }

            return sb.ToString();
        }

        private static string FormatByteWasm(byte b)
        {
            // MASM/WASM-style hex byte literal. Many assemblers require a leading 0 if it starts with A-F.
            var hex = b.ToString("X2", CultureInfo.InvariantCulture);
            if (hex.Length > 0)
            {
                var c = hex[0];
                if (c >= 'A' && c <= 'F')
                    return "0" + hex + "h";
            }
            return hex + "h";
        }

        private static string TranslateAsmToMc0(string asm, string bytesHex)
        {
            var a = (asm ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(a))
                return $"EMITHEX(\"{NormalizeHex(bytesHex).ToLowerInvariant()}\")";

            // Normalize: collapse spaces; keep commas.
            a = Regex.Replace(a, @"\s+", " ");

            // mov r16, seg
            var m = Regex.Match(a, @"^mov\s+(?<dst>[A-Za-z]{2}),\s*(?<src>cs|ds|es|ss)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var dst = m.Groups["dst"].Value.ToUpperInvariant();
                var src = m.Groups["src"].Value.ToUpperInvariant();
                return $"{dst} = {src}";
            }

            // mov seg, r16
            m = Regex.Match(a, @"^mov\s+(?<dst>cs|ds|es|ss),\s*(?<src>[A-Za-z]{2})$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var dst = m.Groups["dst"].Value.ToUpperInvariant();
                var src = m.Groups["src"].Value.ToUpperInvariant();
                return $"{dst} = {src}";
            }

            // mov r16, imm
            m = Regex.Match(a, @"^mov\s+(?<dst>[A-Za-z]{2}),\s*(?<imm>.+)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var dst = m.Groups["dst"].Value.ToUpperInvariant();
                if (TryParseImm16(m.Groups["imm"].Value, out var imm))
                    return $"{dst} = 0x{imm:X4}";
            }

            // int imm
            m = Regex.Match(a, @"^int\s+(?<imm>.+)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                if (TryParseImm16(m.Groups["imm"].Value, out var imm))
                {
                    if (imm <= 0xFF)
                        return $"INT(0x{imm:X2})";
                    return $"INT(0x{imm:X4})";
                }
            }

            // push r16
            m = Regex.Match(a, @"^push\s+(?<reg>[A-Za-z]{2})$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var reg = m.Groups["reg"].Value.ToUpperInvariant();
                return $"PUSH16({reg})";
            }

            // pop r16
            m = Regex.Match(a, @"^pop\s+(?<reg>[A-Za-z]{2})$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var reg = m.Groups["reg"].Value.ToUpperInvariant();
                return $"{reg} = POP16()";
            }

            // jmp label (handles 'short', 'near')
            m = Regex.Match(a, @"^jmp\s+(?:short\s+|near\s+)?(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)$", RegexOptions.IgnoreCase);
            if (m.Success)
                return $"goto {m.Groups["lbl"].Value}";

            // jcc label (handles common aliases + 'short'/'near')
            m = Regex.Match(a, @"^(?<cc>jz|je|jnz|jne|jc|jnc|ja|jae|jb|jbe|jna|jnae|jnb|jnbe|jl|jle|jg|jge|jnl|jnle|jng|jnge|jo|jno|js|jns|jp|jpe|jnp|jpo)\s+(?:short\s+|near\s+)?(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var cc = m.Groups["cc"].Value.ToUpperInvariant();
                var lbl = m.Groups["lbl"].Value;
                return $"if ({cc}()) goto {lbl}";
            }

            // jcxz label (handles 'short', 'near')
            m = Regex.Match(a, @"^jcxz\s+(?:short\s+|near\s+)?(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var lbl = m.Groups["lbl"].Value;
                return $"if (JCXZ()) goto {lbl}";
            }

            // loop/loope/loopne label (handles 'short', 'near' and z/nz aliases)
            m = Regex.Match(a, @"^(?<op>loop|loope|loopz|loopne|loopnz)\s+(?:short\s+|near\s+)?(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)$", RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var op = m.Groups["op"].Value.Trim().ToLowerInvariant();
                var lbl = m.Groups["lbl"].Value;
                op = op switch
                {
                    "loopz" => "loope",
                    "loopnz" => "loopne",
                    _ => op,
                };
                return $"if ({op.ToUpperInvariant()}()) goto {lbl}";
            }

            // call label (handles 'near')
            m = Regex.Match(a, @"^call\s+(?:near\s+)?(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)$", RegexOptions.IgnoreCase);
            if (m.Success)
                return $"CALL({m.Groups["lbl"].Value})";


            // ret / retf
            m = Regex.Match(a, @"^retf$", RegexOptions.IgnoreCase);
            if (m.Success) return "RET_FAR()";
            m = Regex.Match(a, @"^ret$", RegexOptions.IgnoreCase);
            if (m.Success) return "RET_NEAR()";

            // Default: keep as a stable byte-anchored leaf.
            return $"EMITHEX(\"{NormalizeHex(bytesHex).ToLowerInvariant()}\")";
        }

        private static bool TryParseImm16(string token, out ushort value)
        {
            value = 0;
            var s = (token ?? string.Empty).Trim();

            // Trim common decorations: `byte ptr`, `word ptr` etc (we only parse pure immediates here).
            // If it has spaces, this is probably not a pure immediate.
            if (s.Contains(' '))
                return false;

            if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(0, s.Length - 1);

            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);

            if (s.Length == 0)
                return false;

            if (!ushort.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            {
                if (!ushort.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
                    return false;
                value = dec;
                return true;
            }

            value = hex;
            return true;
        }

        private static string ComputeStreamSha256(IReadOnlyList<Mc0Stmt> statements)
        {
            var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            // Reused per-iteration to avoid stackalloc-in-loop (CA2014).
            Span<byte> addrBuf = stackalloc byte[4];

            foreach (var st in statements)
            {
                var addr = st.Addr;
                addrBuf[0] = (byte)(addr & 0xFF);
                addrBuf[1] = (byte)((addr >> 8) & 0xFF);
                addrBuf[2] = (byte)((addr >> 16) & 0xFF);
                addrBuf[3] = (byte)((addr >> 24) & 0xFF);
                h.AppendData(addrBuf);

                var b = ParseHex(st.BytesHex);
                h.AppendData(b);
            }

            return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
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
            if (hex.Length % 2 != 0)
                throw new InvalidDataException("Odd-length hex byte string");

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return bytes;
        }
    }
}
