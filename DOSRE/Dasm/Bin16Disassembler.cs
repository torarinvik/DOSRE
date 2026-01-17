using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Serialization;
using SharpDisasm;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Flat 16-bit binary disassembler (COM-like / raw code blobs).
    /// This intentionally does not attempt to infer segments, relocations, or entrypoints.
    /// </summary>
    public static class Bin16Disassembler
    {
        private enum EnumReasmDialect
        {
            Nasm,
            WasmMasm,
        }

        public sealed class Bin16ReasmExport
        {
            public string input { get; set; }
            public int fileLength { get; set; }
            public uint origin { get; set; }
        }

        public static bool TryExportReassembly(
            string inputFile,
            uint origin,
            string outAsmFile,
            string outJsonFile,
            out string error)
        {
            return TryExportReassembly(inputFile, origin, outAsmFile, outJsonFile, wasmCompat: false, out error);
        }

        public static bool TryExportReassembly(
            string inputFile,
            uint origin,
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
                    error = "Please specify at least one output: -BINREASM <out.asm> and/or -BINREASMJSON <out.json>";
                    return false;
                }

                var fileBytes = File.ReadAllBytes(inputFile);
                if (fileBytes.Length == 0)
                {
                    error = "Input file is empty";
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(outJsonFile))
                {
                    var payload = new Bin16ReasmExport
                    {
                        input = inputFile,
                        fileLength = fileBytes.Length,
                        origin = origin,
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
                    var asm = BuildReasmAsm(inputFile, fileBytes, origin,
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

        private static string BuildReasmAsm(string inputFile, byte[] fileBytes, uint origin, EnumReasmDialect dialect)
        {
            var sb = new StringBuilder();
            sb.AppendLine(dialect == EnumReasmDialect.WasmMasm
                ? "; BIN16 reassembly export (byte-perfect; OpenWatcom WASM/MASM-compatible syntax)"
                : "; BIN16 reassembly export (byte-perfect via NASM -f bin)");
            sb.AppendLine($"; Input: {Path.GetFileName(inputFile)}");
            sb.AppendLine($"; File length: {fileBytes.Length} bytes");
            sb.AppendLine($"; Origin: 0x{origin:X}");
            sb.AppendLine(";");

            if (dialect == EnumReasmDialect.WasmMasm)
            {
                sb.AppendLine("; Notes:");
                sb.AppendLine("; - This file is a raw byte blob. We keep org=0 to avoid implicit padding in MASM-like assemblers.");
                sb.AppendLine("; - The Origin above is the intended load address used during analysis/disassembly (not a file offset).");
                sb.AppendLine("; Build (OpenWatcom):");
                sb.AppendLine(";   wasm source.asm -fo=out.obj");
                sb.AppendLine(";   wlink format raw bin name out.bin file out.obj");
                sb.AppendLine(";");
                sb.AppendLine(".8086");
                sb.AppendLine(".model tiny");
                sb.AppendLine(".code");
                sb.AppendLine("org 0");
            }
            else
            {
                sb.AppendLine("bits 16");
                sb.AppendLine($"org 0x{origin:X}");
            }

            sb.AppendLine("bin16_file:");
            EmitDbBytes(sb, fileBytes, 0, fileBytes.Length, dialect);

            if (dialect == EnumReasmDialect.WasmMasm)
            {
                sb.AppendLine();
                sb.AppendLine("end");
            }
            return sb.ToString();
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

        private sealed class BinString
        {
            public BinString(uint address, int length, string preview)
            {
                Address = address;
                Length = length;
                Preview = preview;
            }

            public uint Address { get; }
            public int Length { get; }
            public string Preview { get; }
        }

        public static bool TryDisassembleToString(
            string inputFile,
            uint origin,
            int? bytesLimit,
            bool masmCompat,
            bool binInsights,
            bool emitInlineStringLabels,
            bool masmCompatEmitInstructions,
            bool masmCompatEmitInstructionComments,
            bool masmCompatEmitCodeMap,
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

            static string ToMasmHexU32(uint value, int minDigits)
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

            static string ToMasmHexU32NoPad(uint value) => ToMasmHexU32(value, 0);
            static string ToMasmHexByte(byte value) => value == 0 ? "00h" : ToMasmHexU32(value, 2);

            static string NormalizeHexLiteralsToMasm(string text)
            {
                if (string.IsNullOrEmpty(text))
                    return text;

                // Replace C-style hex: 0xABCD / -0x10
                text = Regex.Replace(
                    text,
                    @"(?<![0-9A-Fa-f_])(-?)0x([0-9A-Fa-f]+)",
                    m =>
                    {
                        var sign = m.Groups[1].Value;
                        var hex = m.Groups[2].Value.ToUpperInvariant();
                        if (hex == "0")
                            return sign + "0";
                        if (hex.Length > 0)
                        {
                            var c0 = hex[0];
                            if (c0 >= 'A' && c0 <= 'F')
                                hex = "0" + hex;
                        }
                        return sign + hex + "h";
                    },
                    RegexOptions.CultureInvariant);

                return text;
            }

            Dictionary<uint, BinString> stringsByAddr = null;
            if (binInsights)
            {
                stringsByAddr = ScanStrings(fileBytes, origin, minLen: 6, maxCount: 2048, allowTokens: masmCompat);
            }
            else if (masmCompatEmitCodeMap)
            {
                // For -BINMAP we still want a basic idea of where obvious text blobs are,
                // because those can defeat reachability (linear fallthrough) and pointer-table scans.
                // Token support matters for games that embed control bytes inside text (e.g., 03 xx, f0, etc.)
                // otherwise large UI/help text can be missed and later misinterpreted as code.
                stringsByAddr = ScanStrings(fileBytes, origin, minLen: 6, maxCount: 4096, allowTokens: true);
            }

            // Best-effort data region tracking for code map output.
            var dataRegions = new List<(uint start, uint endExcl, string kind, string reason)>();

            void RecordDataRegion(uint start, int length, string kind, string reason)
            {
                if (!masmCompatEmitCodeMap)
                    return;
                if (length <= 0)
                    return;
                dataRegions.Add((start, start + (uint)length, kind ?? "data", reason ?? string.Empty));
            }

            // Mark long ASCII sequences as strong data candidates.
            // Used to avoid reachability walking straight through text blobs.
            bool[] isStrongStringByte = null;
            if (masmCompatEmitCodeMap && stringsByAddr != null && stringsByAddr.Count > 0)
            {
                isStrongStringByte = new bool[code.Length];
                foreach (var s in stringsByAddr.Values)
                {
                    // In -BINMAP, any NUL-terminated token/ASCII string is overwhelmingly likely to be data.
                    // Mark them so reachability doesn't interpret UI/help blobs as code.
                    if (s.Length < 6)
                        continue;
                    if (s.Address < origin)
                        continue;
                    var startPos = (int)(s.Address - origin);
                    if (startPos < 0 || startPos >= code.Length)
                        continue;
                    var len = Math.Min(s.Length, code.Length - startPos);
                    for (var i = 0; i < len; i++)
                        isStrongStringByte[startPos + i] = true;

                    // Also record the region directly as data for the code map.
                    var reason = s.Length >= 24 ? "scan: long ASCII/token string" : "scan: ASCII/token string";
                    RecordDataRegion(s.Address, len, "string", reason);
                }
            }

            // Mark obvious filler/padding regions as strong data candidates.
            // This helps suppress false code reachability into repeated patterns (e.g., F6F6..., 0000...).
            bool[] isStrongFillByte = null;
            if (masmCompatEmitCodeMap && code.Length > 0)
            {
                isStrongFillByte = new bool[code.Length];

                void MarkFillRegion(int startPos, int length, string reason)
                {
                    if (startPos < 0 || startPos >= code.Length || length <= 0)
                        return;
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                        isStrongFillByte[i] = true;
                    RecordDataRegion(origin + (uint)startPos, endPos - startPos, "fill", reason);
                }

                // 1) Long runs of identical bytes.
                for (var i = 0; i < code.Length;)
                {
                    var b = code[i];
                    var j = i + 1;
                    while (j < code.Length && code[j] == b)
                        j++;
                    var len = j - i;
                    if (len >= 64 || (len >= 32 && (b == 0x00 || b == 0xFF || b == 0xF6)))
                        MarkFillRegion(i, len, $"scan: fill run 0x{b:X2} x{len}");
                    i = j;
                }

                // 2) Repeated word patterns (helps with F6F6F6F6... even when not caught above for some reason).
                for (var i = 0; i + 3 < code.Length;)
                {
                    var b0 = code[i];
                    var b1 = code[i + 1];
                    var reps = 1;
                    var j = i + 2;
                    while (j + 1 < code.Length && code[j] == b0 && code[j + 1] == b1)
                    {
                        reps++;
                        j += 2;
                    }

                    if (reps >= 16)
                    {
                        var w = (ushort)(b0 | (b1 << 8));
                        MarkFillRegion(i, reps * 2, $"scan: repeated word 0x{w:X4} x{reps}");
                        i = j;
                        continue;
                    }

                    i++;
                }

                // 3) Bitmap-like blocks: many words have identical low/high bytes (e.g. 3C3C, 1E1E, F0F0, FEFE),
                // but the values vary across the block. These are common for sprites/fonts and can otherwise be
                // misinterpreted as reachable code.
                //
                // Heuristic: within a probe window, require a high ratio of repeated-byte words and a minimum
                // amount of variety (not just 0000/FFFF padding).
                const int bitmapProbeWords = 64; // 128 bytes
                const int bitmapMinWords = 96;   // only carve if the block has some heft

                static ushort ReadU16LE(byte[] bytes, int pos)
                    => (ushort)(bytes[pos] | (bytes[pos + 1] << 8));

                for (var i = 0; i + (bitmapProbeWords * 2) <= code.Length; i += 2)
                {
                    if (isStrongFillByte[i])
                        continue;

                    // Skip if this is already clearly code-adjacent text.
                    if (isStrongStringByte != null && isStrongStringByte[i])
                        continue;

                    int ProbeScore(int startPos, int words)
                    {
                        var repeated = 0;
                        var distinct = new HashSet<byte>();
                        var nonTrivial = 0;

                        var maxWords = Math.Min(words, (code.Length - startPos) / 2);
                        for (var wi = 0; wi < maxWords; wi++)
                        {
                            var p = startPos + (wi * 2);
                            var lo = code[p];
                            var hi = code[p + 1];
                            if (lo == hi)
                            {
                                repeated++;
                                distinct.Add(lo);
                                if (lo != 0x00 && lo != 0xFF)
                                    nonTrivial++;
                            }
                        }

                        // Score is (repeated ratio, variety, non-triviality) folded into a single integer.
                        // This keeps the caller logic simple.
                        if (maxWords < 16)
                            return 0;

                        if (repeated < (int)Math.Ceiling(maxWords * 0.60))
                            return 0;
                        if (distinct.Count < 6)
                            return 0;
                        if (nonTrivial < (int)Math.Ceiling(maxWords * 0.25))
                            return 0;

                        return repeated;
                    }

                    // Fast reject.
                    if (ProbeScore(i, bitmapProbeWords) == 0)
                        continue;

                    // Expand forward while the property broadly holds.
                    var start = i;
                    var endExcl = i + (bitmapProbeWords * 2);
                    while (endExcl + 2 <= code.Length)
                    {
                        // Re-check a probe window anchored near the end to avoid drifting into unrelated data.
                        var anchor = Math.Max(start, endExcl - (bitmapProbeWords * 2));
                        if (ProbeScore(anchor, bitmapProbeWords) == 0)
                            break;

                        // Avoid absorbing already-carved fill runs (we'd just be redundant) and avoid pulling in strings.
                        if (isStrongFillByte[endExcl - 1])
                            break;
                        if (isStrongStringByte != null && isStrongStringByte[endExcl - 1])
                            break;

                        endExcl += 2;
                    }

                    var carvedLen = endExcl - start;
                    if (carvedLen >= (bitmapMinWords * 2))
                    {
                        // Trim a trailing odd byte if any.
                        if ((carvedLen & 1) != 0)
                            carvedLen--;
                        if (carvedLen > 0)
                        {
                            // If the entire region is actually a single repeated word, the earlier scan already handles it.
                            var w0 = ReadU16LE(code, start);
                            var allSame = true;
                            for (var p = start + 2; p + 1 < start + carvedLen; p += 2)
                            {
                                if (ReadU16LE(code, p) != w0)
                                {
                                    allSame = false;
                                    break;
                                }
                            }

                            if (!allSame)
                                MarkFillRegion(start, carvedLen, "scan: bitmap-like repeated-byte word block");
                        }
                    }
                }
            }

            // Mark obvious 3-byte record tables as strong data candidates.
            // Some games store lookup tables as repeating [tag8][value16] records where tag is printable ASCII
            // (e.g. key mappings like 'A'->0x020A). These are not string pointer tables but can still be
            // mistakenly treated as reachable code.
            bool[] isStrongTagWordTblByte = null;
            if (masmCompatEmitCodeMap && code.Length > 0)
            {
                isStrongTagWordTblByte = new bool[code.Length];

                void MarkTagWordTblRegion(int startPos, int length, string reason)
                {
                    if (startPos < 0 || startPos >= code.Length || length <= 0)
                        return;
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                        isStrongTagWordTblByte[i] = true;
                    RecordDataRegion(origin + (uint)startPos, endPos - startPos, "tagwordtbl", reason);
                }

                static bool IsPrintableAscii(byte b) => b >= 0x20 && b <= 0x7E;

                const int minRecords = 10;
                const int maxScanLen = 1024;

                for (var startPos = 0; startPos + (minRecords * 3) <= code.Length; startPos++)
                {
                    if (isStrongTagWordTblByte[startPos])
                        continue;
                    if (isStrongFillByte != null && isStrongFillByte[startPos])
                        continue;
                    if (isStrongStringByte != null && isStrongStringByte[startPos])
                        continue;

                    var tag0 = code[startPos];
                    if (!IsPrintableAscii(tag0))
                        continue;

                    var maxRecordsHere = Math.Min(32, (code.Length - startPos) / 3);
                    if (maxRecordsHere < minRecords)
                        continue;

                    var tagCounts = new Dictionary<byte, int>();
                    var hiCounts = new Dictionary<byte, int>();
                    var records = 0;
                    var nonTrivialValues = 0;

                    for (var r = 0; r < maxRecordsHere; r++)
                    {
                        var rec = startPos + (r * 3);
                        if (rec + 2 >= code.Length)
                            break;

                        var tag = code[rec];
                        if (!IsPrintableAscii(tag))
                            break;

                        // Avoid treating obvious padding as a table.
                        if (tag == 0x20)
                            break;

                        records++;
                        tagCounts[tag] = tagCounts.TryGetValue(tag, out var tc) ? (tc + 1) : 1;

                        var lo = code[rec + 1];
                        var hi = code[rec + 2];
                        hiCounts[hi] = hiCounts.TryGetValue(hi, out var hc) ? (hc + 1) : 1;

                        var val = (ushort)(lo | (hi << 8));
                        if (val != 0x0000 && val != 0xFFFF)
                            nonTrivialValues++;
                    }

                    if (records < minRecords)
                        continue;

                    // Require a reasonably stable tag set.
                    if (tagCounts.Count > 8)
                        continue;

                    var dominantTagCount = 0;
                    foreach (var kv in tagCounts)
                        dominantTagCount = Math.Max(dominantTagCount, kv.Value);
                    if (dominantTagCount < (int)Math.Ceiling(records * 0.50))
                        continue;

                    // Require non-trivial values in most records.
                    if (nonTrivialValues < (int)Math.Ceiling(records * 0.70))
                        continue;

                    var dominantHiCount = 0;
                    foreach (var kv in hiCounts)
                        dominantHiCount = Math.Max(dominantHiCount, kv.Value);
                    if (dominantHiCount < (int)Math.Ceiling(records * 0.50))
                        continue;

                    // Build a small allowed set for extension (avoid drifting into unrelated data).
                    var minTagSupport = Math.Max(2, (int)Math.Ceiling(records * 0.10));
                    var allowedTags = new HashSet<byte>(tagCounts.Where(kv => kv.Value >= minTagSupport).Select(kv => kv.Key));
                    var allowedHis = new HashSet<byte>(hiCounts.Where(kv => kv.Value >= minTagSupport).Select(kv => kv.Key));
                    if (allowedTags.Count == 0 || allowedHis.Count == 0)
                        continue;

                    var len = records * 3;
                    while (startPos + len + 2 < code.Length && len < maxScanLen)
                    {
                        var rec = startPos + len;
                        if (isStrongTagWordTblByte[rec])
                            break;
                        if (isStrongFillByte != null && isStrongFillByte[rec])
                            break;
                        if (isStrongStringByte != null && isStrongStringByte[rec])
                            break;

                        var tag = code[rec];
                        if (!IsPrintableAscii(tag) || !allowedTags.Contains(tag))
                            break;
                        var hi = code[rec + 2];
                        if (!allowedHis.Contains(hi))
                            break;
                        len += 3;
                    }

                    if (len >= minRecords * 3)
                    {
                        MarkTagWordTblRegion(startPos, len, "scan: 3-byte ASCII-tag [tag8][value16] record table");
                        startPos += Math.Max(0, len - 1);
                    }
                }
            }

            // Mark string pointer tables as strong data candidates.
            // Many DOS games reference UI/help text via word tables of pointers into string blobs.
            // Without carving these as data, reachability can fall-through into tables and table scans can mistake them for code pointers.
            bool[] isStrongStrPtrTblByte = null;
            if (masmCompatEmitCodeMap && stringsByAddr != null && stringsByAddr.Count > 0)
            {
                isStrongStrPtrTblByte = new bool[code.Length];

                // Some binaries use fixed-length UI text that is not NUL-terminated.
                // We still want to treat pointer tables into such text regions as data.
                var isTextLikeCache = new Dictionary<uint, bool>();

                bool LooksLikeTextAt(uint addr)
                {
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    if (isTextLikeCache.TryGetValue(addr, out var cached))
                        return cached;

                    var pos = (int)(addr - origin);
                    var max = Math.Min(code.Length, pos + 32);
                    var observed = 0;
                    var printable = 0;
                    var tokens = 0;
                    var ff = 0;

                    for (var i = pos; i < max; i++)
                    {
                        var b = code[i];
                        if (b == 0x00)
                            break;
                        observed++;

                        if (b >= 0x20 && b <= 0x7E)
                            printable++;
                        else if (b < 0x20)
                            tokens++;
                        else
                            tokens++;

                        if (b == 0xFF)
                            ff++;
                    }

                    var ok = true;
                    if (observed < 4)
                    {
                        ok = false;
                    }
                    else if (observed < 12)
                    {
                        // Short fixed-length UI tokens (country codes, abbreviations, etc) are common.
                        // Accept short regions with strong printable density, allowing a few control tokens.
                        if (printable < 3)
                            ok = false;
                        else if (printable < (int)Math.Ceiling(observed * 0.60))
                            ok = false;
                        else if (tokens > (printable * 4))
                            ok = false;
                        else if (ff > 0)
                            ok = false;
                    }
                    else
                    {
                        if (printable < 8)
                            ok = false;
                        else if (printable < (int)(observed * 0.35))
                            ok = false;
                        else if (tokens > (printable * 3))
                            ok = false;
                        else if (ff > 4)
                            ok = false;
                    }

                    isTextLikeCache[addr] = ok;
                    return ok;
                }

                bool IsStringLikeTarget(uint addr)
                    => (stringsByAddr != null && stringsByAddr.ContainsKey(addr)) || LooksLikeTextAt(addr);

                void MarkStrPtrTblRegion(int startPos, int length, string reason)
                {
                    if (startPos < 0 || startPos >= code.Length || length <= 0)
                        return;
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                        isStrongStrPtrTblByte[i] = true;
                    RecordDataRegion(origin + (uint)startPos, endPos - startPos, "strptrtbl", reason);
                }

                bool TryDetectStringPointerTable(int startPos, out int byteLen, out bool relative)
                {
                    byteLen = 0;
                    relative = false;
                    if (startPos < 0 || startPos + 16 > code.Length)
                        return false;

                    // Many pointer tables are word-aligned, but tagged record tables (e.g. 3-byte [tag][ptr16])
                    // can legally start at odd addresses. We'll still require word alignment for word-based
                    // scanning, but allow tagged-record detection on odd starts.
                    var a = origin + (uint)startPos;
                    var isWordAligned = (a & 1) == 0;

                    // Avoid obviously carved regions.
                    if (isStrongFillByte != null && isStrongFillByte[startPos])
                        return false;
                    if (isStrongStringByte != null && isStrongStringByte[startPos])
                        return false;

                    // Use a larger window than codeptrtbl; string pointer tables are often smaller/sparser.
                    var windowLen = 128;
                    if (startPos + windowLen > code.Length)
                        windowLen = code.Length - startPos;
                    if (windowLen < 32)
                        return false;

                    // Additional fallback: byte-tagged pointer records.
                    // Supports both [tag][ptr16] and [ptr16][tag] layouts.
                    bool TryDetectTaggedPtrRecords(int recordSize, int ptrOffset, int tagOffset, out int outLen, out bool outRel)
                    {
                        outLen = 0;
                        outRel = false;

                        if (recordSize < 3)
                            return false;
                        if (ptrOffset < 0 || ptrOffset + 1 >= recordSize)
                            return false;
                        if (tagOffset < 0 || tagOffset >= recordSize)
                            return false;
                        if (startPos + recordSize * 8 > code.Length)
                            return false;

                        var sampleRecords = Math.Min(32, windowLen / recordSize);
                        if (sampleRecords < 8)
                            return false;

                        var absH = 0;
                        var relH = 0;
                        var cons = 0;

                        // Stop early if we drift into non-string data.
                        var missStreak = 0;

                        // Track tag distribution to avoid false positives.
                        // Some tables use a control tag (<0x20), others use a stable printable/separator byte (e.g. 0x41).
                        var tagCounts = new Dictionary<byte, int>();
                        var tagObserved = 0;
                        var recordsVisited = 0;

                        for (var r = 0; r < sampleRecords; r++)
                        {
                            var rec = startPos + (r * recordSize);
                            if (rec + recordSize > code.Length)
                                break;

                            recordsVisited++;

                            var tag = code[rec + tagOffset];
                            // Tags are game-specific. We accept any non-zero/non-FF tag byte,
                            // and later require a dominant tag value plus strong pointer-to-text evidence.
                            if (tag == 0x00 || tag == 0xFF)
                            {
                                if (tagObserved > 0)
                                    break;
                                continue;
                            }

                            tagObserved++;
                            if (!tagCounts.TryGetValue(tag, out var tc))
                                tc = 0;
                            tagCounts[tag] = tc + 1;

                            var p = rec + ptrOffset;
                            var lo = code[p];
                            var hi = code[p + 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                                continue;

                            cons++;
                            var abs = (uint)val;
                            var rel = origin + abs;
                            var absOk = IsStringLikeTarget(abs);
                            var relOk = IsStringLikeTarget(rel);
                            if (absOk)
                                absH++;
                            if (relOk)
                                relH++;

                            if (!absOk && !relOk)
                            {
                                missStreak++;
                                if (missStreak >= 6)
                                    break;
                            }
                            else
                            {
                                missStreak = 0;
                            }
                        }

                        if (cons < 6)
                            return false;

                        // Require that most records have a valid tag byte.
                        if (tagObserved < 6 || tagCounts.Count == 0)
                            return false;

                        // Most records should look tagged.
                        if (recordsVisited >= 8 && tagObserved < (int)Math.Ceiling(recordsVisited * 0.70))
                            return false;

                        // If tags are extremely diverse, it's likely random data.
                        if (tagCounts.Count > Math.Min(16, tagObserved))
                            return false;

                        // Require a dominant tag byte to avoid accidental matches in code streams.
                        var dominantCount = 0;
                        foreach (var kv in tagCounts)
                            dominantCount = Math.Max(dominantCount, kv.Value);
                        if (dominantCount < (int)Math.Ceiling(tagObserved * 0.60))
                            return false;

                        var bestH = Math.Max(absH, relH);
                        // Tagged record regions can be mixed; require some hits but allow a lower density.
                        if (bestH < 4 || bestH < (int)Math.Ceiling(cons * 0.35))
                            return false;

                        outRel = relH > absH;

                        // Conservative extension: only extend while the next record's pointer still lands in text.
                        // This avoids expanding into adjacent non-string data which can tank the hit ratio.
                        var len = sampleRecords * recordSize;
                        var hits = bestH;
                        var cons2 = cons;
                        while (startPos + len + recordSize <= code.Length && len < 1024)
                        {
                            var rec = startPos + len;
                            var tag = code[rec + tagOffset];
                            if (tag == 0x00 || tag >= 0x20)
                                break;

                            var p = rec + ptrOffset;
                            var lo = code[p];
                            var hi = code[p + 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                            {
                                len += recordSize;
                                continue;
                            }

                            var abs = (uint)val;
                            var tgt = outRel ? (origin + abs) : abs;
                            if (!IsStringLikeTarget(tgt))
                                break;

                            cons2++;
                            hits++;
                            len += recordSize;
                        }

                        outLen = len;
                        if (outLen < recordSize * 8)
                            return false;
                        if (hits < 4 || hits < (int)Math.Ceiling(cons2 * 0.35))
                            return false;

                        return true;
                    }

                    // If not word-aligned, only try tagged-record detection.
                    if (!isWordAligned)
                    {
                        if (TryDetectTaggedPtrRecords(recordSize: 3, ptrOffset: 1, tagOffset: 0, out var recLenA, out var recRelA))
                        {
                            byteLen = recLenA;
                            relative = recRelA;
                            return true;
                        }
                        if (TryDetectTaggedPtrRecords(recordSize: 3, ptrOffset: 0, tagOffset: 2, out var recLenB, out var recRelB))
                        {
                            byteLen = recLenB;
                            relative = recRelB;
                            return true;
                        }
                        return false;
                    }

                    var words = windowLen / 2;
                    var absHits = 0;
                    var relHits = 0;
                    var considered = 0;

                    // Detect strided tables/record arrays where only every Nth word is a string pointer.
                    // Example layout: [tag][ptr][meta] repeated (6-byte records => strideWords=3, ptrWordOffset=1).
                    // We'll use this both as a fallback (when the contiguous detector is weak) and as a preference
                    // (when the contiguous detector passes but would truncate early due to interleaved meta words).
                    bool TryDetectStrided(int strideWords, int ptrWordOffset, out int outLen, out bool outRel)
                    {
                        outLen = 0;
                        outRel = false;

                        if (strideWords < 2)
                            return false;

                        var strideBytes = strideWords * 2;
                        if (startPos + strideBytes * 6 > code.Length)
                            return false;

                        // Only sample locally (within the same evidence window as the contiguous detector).
                        // Scanning too far tends to run past the real table into unrelated data and destroys the hit ratio.
                        var sampleRecords = Math.Min(24, windowLen / strideBytes);
                        if (sampleRecords < 6)
                            return false;

                        var absH = 0;
                        var relH = 0;
                        var cons = 0;

                        for (var r = 0; r < sampleRecords; r++)
                        {
                            var p = startPos + (r * strideBytes) + (ptrWordOffset * 2);
                            if (p + 1 >= code.Length)
                                break;
                            var lo = code[p];
                            var hi = code[p + 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                                continue;
                            cons++;

                            var abs = (uint)val;
                            var rel = origin + abs;
                            if (IsStringLikeTarget(abs))
                                absH++;
                            if (IsStringLikeTarget(rel))
                                relH++;
                        }

                        if (cons < 6)
                            return false;

                        var bestH = Math.Max(absH, relH);
                        if (bestH < 4 || bestH < (int)Math.Ceiling(cons * 0.60))
                            return false;

                        outRel = relH > absH;

                        // Extend record-by-record while the pointer field keeps mostly landing in text.
                        var len = sampleRecords * strideBytes;
                        var hits = bestH;
                        var missStreak = 0;
                        var cons2 = cons;
                        while (startPos + len + strideBytes <= code.Length && len < 1024)
                        {
                            var p = startPos + len + (ptrWordOffset * 2);
                            if (p + 1 >= code.Length)
                                break;
                            var lo = code[p];
                            var hi = code[p + 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                            {
                                len += strideBytes;
                                continue;
                            }

                            cons2++;
                            var abs = (uint)val;
                            var tgt = outRel ? (origin + abs) : abs;
                            if (IsStringLikeTarget(tgt))
                            {
                                hits++;
                                missStreak = 0;
                                len += strideBytes;
                                continue;
                            }

                            missStreak++;
                            if (missStreak >= 3)
                                break;
                            len += strideBytes;
                        }

                        outLen = len;
                        if (outLen < strideBytes * 6)
                            return false;
                        if (hits < 4 || hits < (int)Math.Ceiling(cons2 * 0.60))
                            return false;
                        return true;
                    }

                    for (var w = 0; w < words; w++)
                    {
                        var lo = code[startPos + (w * 2)];
                        var hi = code[startPos + (w * 2) + 1];
                        var val = (ushort)(lo | (hi << 8));
                        if (val == 0x0000 || val == 0xFFFF)
                            continue;
                        considered++;

                        var abs = (uint)val;
                        var rel = origin + abs;
                        if (IsStringLikeTarget(abs))
                            absHits++;
                        if (IsStringLikeTarget(rel))
                            relHits++;
                    }

                    if (considered < 6)
                        return false;

                    var best = Math.Max(absHits, relHits);

                    // If this region actually looks like a strided record table (e.g. [tag][ptr][meta]), prefer that.
                    // This prevents the contiguous detector from succeeding but then truncating early due to meta words.
                    var contRatio = best == 0 ? 0.0 : (double)best / Math.Max(1, considered);
                    if (contRatio < 0.75)
                    {
                        for (var strideWords = 2; strideWords <= 5; strideWords++)
                        {
                            for (var ptrOff = 0; ptrOff < strideWords; ptrOff++)
                            {
                                if (TryDetectStrided(strideWords, ptrOff, out var sLen, out var sRel))
                                {
                                    byteLen = sLen;
                                    relative = sRel;
                                    return true;
                                }
                            }
                        }
                    }

                    // Require a decent density of string pointers.
                    if (best < 4 || best < (int)Math.Ceiling(considered * 0.50))
                    {
                        // Fallback: sparse/mixed-mode pointer blobs.
                        // Some tables interleave constants with a few real string pointers, and may even mix
                        // absolute and origin-relative offsets. If we see a couple of *known* strings referenced
                        // in the local window, treat the region as data.
                        bool TryDetectSparseMixedWordPtrs(out int outLen, out bool outRel)
                        {
                            outLen = 0;
                            outRel = false;
                            if (stringsByAddr == null || stringsByAddr.Count == 0)
                                return false;

                            // Heuristic: this fallback is intentionally permissive for mixed data blobs,
                            // but it should not fire on obvious instruction streams (e.g. DOS INT 21h setup).
                            // If the local bytes look very code-like, treat this as not-a-table and let
                            // reachability handle it.
                            bool LooksLikeLikelyCodeStart(int pos)
                            {
                                var n = Math.Min(12, code.Length - pos);
                                if (n < 6)
                                    return false;

                                var score = 0;
                                for (var i = 0; i < n; i++)
                                {
                                    var b = code[pos + i];
                                    if (b == 0xCD || b == 0xE8 || b == 0xE9 || b == 0xEB || b == 0xC3 || b == 0xCB || b == 0xFA || b == 0xFB)
                                        score++;
                                    else if (b == 0x8B || b == 0x89 || b == 0x8E || b == 0x9A)
                                        score++;
                                    else if (b == 0xF3 || b == 0xF2)
                                        score++;
                                    else if (b >= 0x70 && b <= 0x7F) // short Jcc
                                        score++;
                                    else if (b >= 0xB0 && b <= 0xBF) // mov r8/16, imm
                                        score++;
                                }

                                // Require a fairly high score to avoid rejecting real data that happens to contain
                                // a couple of common opcode bytes.
                                return score >= 5;
                            }

                            if (LooksLikeLikelyCodeStart(startPos))
                                return false;

                            var probeWords = Math.Min(16, words);
                            if (probeWords < 6)
                                return false;

                            var absH = 0;
                            var relH = 0;
                            var anyH = 0;
                            var strongLenSum = 0;
                            var strongHits = 0;
                            var sentinelWords = 0;
                            var highBitWords = 0;
                            var consProbe = 0;
                            var maxTextLen = 0;

                            int TextRunLen(uint addr)
                            {
                                if (addr < origin || addr >= origin + (uint)code.Length)
                                    return 0;
                                var pos = (int)(addr - origin);
                                var max = Math.Min(code.Length, pos + 64);
                                var n = 0;
                                for (var i = pos; i < max; i++)
                                {
                                    if (code[i] == 0x00)
                                        break;
                                    n++;
                                }
                                return n;
                            }

                            for (var w = 0; w < probeWords; w++)
                            {
                                var lo = code[startPos + (w * 2)];
                                var hi = code[startPos + (w * 2) + 1];
                                var val = (ushort)(lo | (hi << 8));
                                if (val == 0x0000 || val == 0xFFFF)
                                {
                                    sentinelWords++;
                                    continue;
                                }

                                consProbe++;
                                if ((val & 0x8000) != 0)
                                    highBitWords++;

                                var abs = (uint)val;
                                var rel = origin + abs;
                                var absOk = IsStringLikeTarget(abs);
                                var relOk = IsStringLikeTarget(rel);
                                if (absOk)
                                    absH++;
                                if (relOk)
                                    relH++;

                                if (absOk || relOk)
                                {
                                    anyH++;
                                    var l = Math.Max(absOk ? TextRunLen(abs) : 0, relOk ? TextRunLen(rel) : 0);
                                    if (l > maxTextLen)
                                        maxTextLen = l;

                                    if (stringsByAddr.TryGetValue(abs, out var absStr) && absStr.Length >= 6)
                                    {
                                        strongHits++;
                                        strongLenSum += absStr.Length;
                                    }
                                    else if (stringsByAddr.TryGetValue(rel, out var relStr) && relStr.Length >= 6)
                                    {
                                        strongHits++;
                                        strongLenSum += relStr.Length;
                                    }
                                }
                            }

                            if (consProbe < 4)
                                return false;

                            // Guardrail: sparse blobs often contain a few sentinel words, but some UI/data tables don't.
                            // If there are no obvious sentinels, require other strong evidence of a data-like blob.
                            if (sentinelWords < 1 && highBitWords < 4)
                                return false;

                            // Require evidence of at least one decent text target.
                            if (strongHits < 1 && maxTextLen < 12)
                                return false;

                            // Allow either:
                            // - 2+ string-like hits (classic sparse table)
                            // - 1 hit if surrounded by record-ish values (high-bit words are common in flags/bitmasks)
                            if (anyH < 2)
                            {
                                if (anyH < 1)
                                    return false;
                                if (maxTextLen < 8)
                                    return false;
                                if (highBitWords < 4)
                                    return false;
                            }
                            else
                            {
                                if (strongHits < 1 || strongLenSum < 12)
                                    return false;
                            }

                            outRel = relH >= absH;

                            // Extend word-by-word with a small miss budget.
                            var len = 0;
                            var hits = 0;
                            var missStreak = 0;
                            var cons2 = 0;
                            while (startPos + len + 2 <= code.Length && len < 128)
                            {
                                var lo = code[startPos + len];
                                var hi = code[startPos + len + 1];
                                var val = (ushort)(lo | (hi << 8));
                                if (val == 0x0000 || val == 0xFFFF)
                                {
                                    len += 2;
                                    continue;
                                }

                                cons2++;
                                var abs = (uint)val;
                                var rel = origin + abs;
                                if (IsStringLikeTarget(abs) || IsStringLikeTarget(rel))
                                {
                                    hits++;
                                    missStreak = 0;
                                    len += 2;
                                    continue;
                                }

                                missStreak++;
                                if (missStreak >= 5)
                                    break;
                                len += 2;
                            }

                            var requiredHits = anyH >= 2 ? 2 : 1;
                            if (hits < requiredHits || cons2 < 4)
                                return false;

                            outLen = len;
                            return outLen >= 12;
                        }

                        if (TryDetectSparseMixedWordPtrs(out var sparseLen, out var sparseRel))
                        {
                            byteLen = sparseLen;
                            relative = sparseRel;
                            return true;
                        }

                        // Try a few common record layouts.
                        for (var strideWords = 2; strideWords <= 5; strideWords++)
                        {
                            for (var ptrOff = 0; ptrOff < strideWords; ptrOff++)
                            {
                                if (TryDetectStrided(strideWords, ptrOff, out var sLen, out var sRel))
                                {
                                    byteLen = sLen;
                                    relative = sRel;
                                    return true;
                                }
                            }
                        }

                        // Additional fallback: word-tagged records: [tag16][ptr16][meta16] repeating (6-byte records).
                        // Decathlon has UI record blobs where only one word per record is a string pointer.
                        bool TryDetectWordTaggedPtrRecords6(out int outLen, out bool outRel)
                        {
                            outLen = 0;
                            outRel = false;

                            const int recordSize = 6;
                            const int ptrOffset = 2;
                            if (startPos + recordSize * 8 > code.Length)
                                return false;

                            var sampleRecords = Math.Min(32, windowLen / recordSize);
                            if (sampleRecords < 8)
                                return false;

                            var absH = 0;
                            var relH = 0;
                            var cons = 0;

                            // Track a dominant tag word pattern (typically 0x0107, 0x0117, ...)
                            var tagCounts = new Dictionary<ushort, int>();
                            var tagObserved = 0;

                            for (var r = 0; r < sampleRecords; r++)
                            {
                                var rec = startPos + (r * recordSize);
                                if (rec + recordSize > code.Length)
                                    break;

                                var tagLo = code[rec];
                                var tagHi = code[rec + 1];
                                var tag = (ushort)(tagLo | (tagHi << 8));

                                // Tag bytes are typically small control values.
                                if (tagLo == 0x00 || tagLo >= 0x20 || tagHi > 0x03)
                                    continue;

                                tagObserved++;
                                if (!tagCounts.TryGetValue(tag, out var tc))
                                    tc = 0;
                                tagCounts[tag] = tc + 1;

                                var p = rec + ptrOffset;
                                var lo = code[p];
                                var hi = code[p + 1];
                                var val = (ushort)(lo | (hi << 8));
                                if (val == 0x0000 || val == 0xFFFF)
                                    continue;

                                cons++;
                                var abs = (uint)val;
                                var rel = origin + abs;
                                if (IsStringLikeTarget(abs))
                                    absH++;
                                if (IsStringLikeTarget(rel))
                                    relH++;
                            }

                            if (cons < 8)
                                return false;
                            if (tagObserved < 8 || tagCounts.Count == 0)
                                return false;

                            var dominantTag = (ushort)0;
                            var dominantCount = 0;
                            foreach (var kv in tagCounts)
                            {
                                if (kv.Value > dominantCount)
                                {
                                    dominantTag = kv.Key;
                                    dominantCount = kv.Value;
                                }
                            }

                            // Require a stable tag pattern.
                            if (dominantCount < (int)Math.Ceiling(sampleRecords * 0.60))
                                return false;

                            var bestH = Math.Max(absH, relH);
                            // Record blobs can be mixed; require some hits but allow a lower density.
                            if (bestH < 4 || bestH < (int)Math.Ceiling(cons * 0.30))
                                return false;

                            outRel = relH > absH;

                            // Extend record-by-record with a small miss budget.
                            var len = sampleRecords * recordSize;
                            var hits = bestH;
                            var cons2 = cons;
                            var missStreak = 0;
                            while (startPos + len + recordSize <= code.Length && len < 1536)
                            {
                                var rec = startPos + len;
                                var tagLo = code[rec];
                                var tagHi = code[rec + 1];

                                // Stop when the tag pattern breaks.
                                if (tagLo == 0x00 || tagLo >= 0x20 || tagHi > 0x03)
                                    break;

                                var p = rec + ptrOffset;
                                var lo = code[p];
                                var hi = code[p + 1];
                                var val = (ushort)(lo | (hi << 8));
                                if (val == 0x0000 || val == 0xFFFF)
                                {
                                    len += recordSize;
                                    continue;
                                }

                                cons2++;
                                var abs = (uint)val;
                                var tgt = outRel ? (origin + abs) : abs;
                                if (IsStringLikeTarget(tgt))
                                {
                                    hits++;
                                    missStreak = 0;
                                    len += recordSize;
                                    continue;
                                }

                                missStreak++;
                                if (missStreak >= 3)
                                    break;
                                len += recordSize;
                            }

                            outLen = len;
                            if (outLen < recordSize * 8)
                                return false;
                            if (hits < 4 || hits < (int)Math.Ceiling(cons2 * 0.30))
                                return false;

                            return true;
                        }

                        // The common layout we see is 3-byte records: [tag][lo][hi].
                        if (TryDetectTaggedPtrRecords(recordSize: 3, ptrOffset: 1, tagOffset: 0, out var recLen, out var recRel))
                        {
                            byteLen = recLen;
                            relative = recRel;
                            return true;
                        }

                        // Alternative common layout: 3-byte records: [lo][hi][tag].
                        if (TryDetectTaggedPtrRecords(recordSize: 3, ptrOffset: 0, tagOffset: 2, out var recLen2, out var recRel2))
                        {
                            byteLen = recLen2;
                            relative = recRel2;
                            return true;
                        }

                        if (TryDetectWordTaggedPtrRecords6(out var rec6Len, out var rec6Rel))
                        {
                            byteLen = rec6Len;
                            relative = rec6Rel;
                            return true;
                        }

                        return false;
                    }

                    relative = relHits > absHits;

                    // Extend while entries keep mostly pointing at strings (allowing occasional 0/FFFF and a few misses).
                    var len = words * 2;
                    var hits = best;
                    var missStreak = 0;
                    var considered2 = considered;
                    while (startPos + len + 2 <= code.Length && len < 512)
                    {
                        var lo = code[startPos + len];
                        var hi = code[startPos + len + 1];
                        var val = (ushort)(lo | (hi << 8));
                        if (val == 0x0000 || val == 0xFFFF)
                        {
                            len += 2;
                            continue;
                        }

                        considered2++;
                        var abs = (uint)val;
                        var tgt = relative ? (origin + abs) : abs;
                        if (IsStringLikeTarget(tgt))
                        {
                            hits++;
                            missStreak = 0;
                            len += 2;
                            continue;
                        }

                        missStreak++;
                        if (missStreak >= 3)
                            break;

                        // Allow a couple of non-string entries inside the table.
                        len += 2;
                    }

                    byteLen = len;
                    if (byteLen < 16)
                        return false;
                    if (hits < 4 || hits < (int)Math.Ceiling(considered2 * 0.50))
                        return false;
                    return true;
                }

                for (var p = 0; p + 32 <= code.Length;)
                {
                    if (TryDetectStringPointerTable(p, out var tblLen, out var relMode))
                    {
                        // Extend backwards a bit: tables sometimes have a few leading entries (sentinels / empty-string ptrs)
                        // that can cause detection to only trigger a couple of words later.
                        var startPos = p;
                        var len = tblLen;
                        var backWords = 0;
                        while (startPos - 2 >= 0 && backWords < 16)
                        {
                            var lo = code[startPos - 2];
                            var hi = code[startPos - 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                            {
                                startPos -= 2;
                                len += 2;
                                backWords++;
                                continue;
                            }

                            var abs = (uint)val;
                            var tgt = relMode ? (origin + abs) : abs;
                            if (IsStringLikeTarget(tgt))
                            {
                                startPos -= 2;
                                len += 2;
                                backWords++;
                                continue;
                            }

                            // Also accept a leading pointer to an empty-string sentinel (0x00 at target).
                            if (tgt >= origin && tgt < origin + (uint)code.Length)
                            {
                                var tpos = (int)(tgt - origin);
                                if (tpos >= 0 && tpos < code.Length && code[tpos] == 0x00)
                                {
                                    startPos -= 2;
                                    len += 2;
                                    backWords++;
                                    continue;
                                }
                            }

                            break;
                        }

                        MarkStrPtrTblRegion(startPos, len, $"scan: word table of {(relMode ? "relative" : "absolute")} string pointers");
                        p = startPos + len;
                        continue;
                    }

                    // Scan byte-by-byte so we can catch odd-aligned record formats like [tag][ptr16]...
                    p += 1;
                }
            }

            var dis = new SharpDisasm.Disassembler(code, ArchitectureMode.x86_16, origin, true);
            var instructions = dis.Disassemble().ToList();
            var insByAddr = instructions
                .GroupBy(i => (uint)i.Offset)
                .Select(g => g.First())
                .ToDictionary(i => (uint)i.Offset, i => i);

            var labelTargets = new HashSet<uint>();
            var functionStarts = new HashSet<uint> { origin };
            var callXrefs = new Dictionary<uint, List<uint>>();
            var jumpXrefs = new Dictionary<uint, List<uint>>();
            var labelByAddr = new Dictionary<uint, string>();
            var referencedStringAddrs = new HashSet<uint>();
            var reachableInsAddrs = new HashSet<uint>();

            // Checklist-driven low-level behavior summaries.
            var interruptVectors = new Dictionary<byte, int>();
            var portIoCount = 0;
            var portImm8Counts = new Dictionary<byte, int>();
            var farCallCount = 0;
            var farJmpCount = 0;

            // Absolute memory references (e.g. word [0x1234]) are very often data.
            // Track them as xrefs to help code/data separation.
            var absMemXrefs = new Dictionary<uint, List<uint>>(); // target -> sources
            var absMemWrites = new Dictionary<uint, List<uint>>(); // target -> sources (likely store)

            // Extra entrypoints discovered from data scans (e.g., jump tables).
            var extraEntryPoints = new HashSet<uint>();
            var jumpTableAnchors = new List<(uint insAddr, uint candidateAddr, string kind)>();
            var indirectJmpCount = 0;
            var indirectCallCount = 0;

            // In instruction modes we may need labels to keep OpenWatcom WASM happy (some rel targets require labels).
            // In comment-only mnemonic mode, labels are optional but nice for readability.
            var emitAsmLabels = masmCompat && (masmCompatEmitInstructions || masmCompatEmitInstructionComments);

            if (binInsights || emitAsmLabels || masmCompatEmitCodeMap)
            {
                static bool TryExtractAbsoluteMemRefFromText(string insText, out uint target)
                {
                    target = 0;
                    if (string.IsNullOrWhiteSpace(insText))
                        return false;

                    // SharpDisasm typically formats absolute disp16 as: "word [0x1234]" or "[0x1234]".
                    // Only accept pure bracket literals (no + / - inside).
                    var m = Regex.Match(insText, @"\[(0x[0-9A-Fa-f]+)\]", RegexOptions.CultureInvariant);
                    if (!m.Success)
                        return false;

                    var inside = m.Groups[1].Value;
                    if (!inside.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        return false;
                    if (!uint.TryParse(inside.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var val))
                        return false;

                    target = val;
                    return true;
                }

                static bool TryCountLowLevelBehavior(Instruction ins, Dictionary<byte, int> intVecs, ref int portIo, ref int farCalls, ref int farJmps)
                {
                    var b = ins.Bytes;
                    if (b == null || b.Length == 0)
                        return false;

                    var i = 0;
                    while (i < b.Length && IsPrefixByte(b[i]))
                        i++;
                    if (i >= b.Length)
                        return false;

                    var op0 = b[i];

                    // INT imm8
                    if (op0 == 0xCD && i + 1 < b.Length)
                    {
                        var vec = b[i + 1];
                        if (!intVecs.TryGetValue(vec, out var c))
                            c = 0;
                        intVecs[vec] = c + 1;
                        return true;
                    }

                    // IN/OUT
                    if (op0 is 0xE4 or 0xE5 or 0xE6 or 0xE7 or 0xEC or 0xED or 0xEE or 0xEF)
                    {
                        portIo++;
                        return true;
                    }

                    // Far CALL/JMP (ptr16:16)
                    if (op0 == 0x9A)
                    {
                        farCalls++;
                        return true;
                    }
                    if (op0 == 0xEA)
                    {
                        farJmps++;
                        return true;
                    }

                    return false;
                }

                static bool IsLikelyWriteToAbsMem(string insText)
                {
                    if (string.IsNullOrWhiteSpace(insText))
                        return false;

                    var mnemonicTok = insText.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault() ?? string.Empty;

                    if (string.IsNullOrEmpty(mnemonicTok))
                        return false;

                    var afterMnemonic = insText.Length > mnemonicTok.Length
                        ? insText.Substring(mnemonicTok.Length).TrimStart()
                        : string.Empty;

                    // Only treat as a write if the first operand is memory.
                    if (!(afterMnemonic.StartsWith("[", StringComparison.Ordinal) ||
                          afterMnemonic.StartsWith("byte [", StringComparison.OrdinalIgnoreCase) ||
                          afterMnemonic.StartsWith("word [", StringComparison.OrdinalIgnoreCase)))
                        return false;

                    // Exclude pure reads/flags-only ops.
                    if (mnemonicTok.Equals("cmp", StringComparison.OrdinalIgnoreCase) ||
                        mnemonicTok.Equals("test", StringComparison.OrdinalIgnoreCase))
                        return false;

                    // Common store/update ops.
                    return mnemonicTok.Equals("mov", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("add", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("sub", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("xor", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("or", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("and", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("inc", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("dec", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("shl", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("shr", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("sar", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("rol", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("ror", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("rcl", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("rcr", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("not", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("neg", StringComparison.OrdinalIgnoreCase) ||
                           mnemonicTok.Equals("xchg", StringComparison.OrdinalIgnoreCase);
                }

                foreach (var ins in instructions)
                {
                    if (masmCompatEmitCodeMap)
                    {
                        // Gather a few critical low-level behaviors (interrupts, port I/O, far transfers).
                        TryCountLowLevelBehavior(ins, interruptVectors, ref portIoCount, ref farCallCount, ref farJmpCount);

                        // Immediate-port histogram (IN/OUT imm8).
                        var b = ins.Bytes;
                        if (b != null && b.Length >= 2)
                        {
                            var i = 0;
                            while (i < b.Length && IsPrefixByte(b[i]))
                                i++;
                            if (i + 1 < b.Length)
                            {
                                var op0 = b[i];
                                if (op0 is 0xE4 or 0xE5 or 0xE6 or 0xE7)
                                {
                                    var port = b[i + 1];
                                    if (!portImm8Counts.TryGetValue(port, out var c))
                                        c = 0;
                                    portImm8Counts[port] = c + 1;
                                }
                            }
                        }

                        // Capture absolute memory references as best-effort data xrefs.
                        // We accept either "disp" as absolute offset, or origin+disp (some binaries treat literals as file-relative).
                        // Keep only those that point inside the currently-disassembled image.
                        var insText = ins.ToString();
                        if (TryExtractAbsoluteMemRefFromText(insText, out var absDisp))
                        {
                            foreach (var cand in new[] { absDisp, origin + absDisp }.Distinct())
                            {
                                if (cand < origin || cand >= origin + (uint)code.Length)
                                    continue;
                                if (!absMemXrefs.TryGetValue(cand, out var sources))
                                    absMemXrefs[cand] = sources = new List<uint>();
                                sources.Add((uint)ins.Offset);

                                if (IsLikelyWriteToAbsMem(insText))
                                {
                                    if (!absMemWrites.TryGetValue(cand, out var wsrc))
                                        absMemWrites[cand] = wsrc = new List<uint>();
                                    wsrc.Add((uint)ins.Offset);
                                }
                            }
                        }
                    }

                    if (!TryGetRelativeBranchTarget16(ins, out var target, out var isCall))
                        continue;

                    if (target < origin || target >= origin + (uint)code.Length)
                        continue;

                    if (binInsights || masmCompatEmitCodeMap)
                    {
                        if (isCall)
                        {
                            functionStarts.Add(target);
                            if (!callXrefs.TryGetValue(target, out var callers))
                                callXrefs[target] = callers = new List<uint>();
                            callers.Add((uint)ins.Offset);
                        }
                        else
                        {
                            labelTargets.Add(target);
                            if (!jumpXrefs.TryGetValue(target, out var sources))
                                jumpXrefs[target] = sources = new List<uint>();
                            sources.Add((uint)ins.Offset);
                        }
                    }
                    else if (emitAsmLabels)
                    {
                        // OpenWatcom WASM requires labels (not numeric targets) for CALL and JCXZ/LOOP*.
                        // Only emit labels when the target is a decoded instruction boundary.
                        if (RequiresLabelForWatcomRelTarget16(ins) && insByAddr.ContainsKey(target))
                            labelTargets.Add(target);
                    }
                }

                // Heuristic: common function prologue in 16-bit code
                if (binInsights)
                {
                    for (var i = 0; i + 1 < instructions.Count; i++)
                    {
                        var b0 = instructions[i].Bytes;
                        var b1 = instructions[i + 1].Bytes;
                        if (b0?.Length >= 1 && b0[0] == 0x55 && b1?.Length >= 2 && b1[0] == 0x8B && b1[1] == 0xEC)
                            functionStarts.Add((uint)instructions[i].Offset);
                    }

                    // Build a stable label map (prefer function labels over loc labels).
                    foreach (var t in labelTargets)
                        labelByAddr[t] = $"loc_{t:X5}";
                    foreach (var f in functionStarts)
                        labelByAddr[f] = $"func_{f:X5}";
                }
                else
                {
                    // In -BININSTR mode, we need labels for relative targets to keep WASM happy
                    // (notably JCXZ/LOOP* do not accept numeric targets).
                    foreach (var t in labelTargets)
                        labelByAddr[t] = $"loc_{t:X5}";
                }
            }

            bool TryDetectCodePointerTableWithThresholds(int startPos, int minWords, int minTargets, int minByteLen, out int byteLen, out List<uint> targets)
            {
                byteLen = 0;
                targets = null;

                if (!masmCompatEmitCodeMap)
                    return false;
                if (startPos < 0 || startPos + minByteLen > code.Length)
                    return false;

                // Word tables are typically even-aligned.
                var a = origin + (uint)startPos;
                if ((a & 1) != 0)
                    return false;

                // Require at least minWords and allow extension.
                var maxLen = Math.Min(512, code.Length - startPos);
                var windowLen = Math.Min(64, maxLen);
                var words = windowLen / 2;
                if (words < minWords)
                    return false;

                // Reject ASCII-heavy regions (very likely text / strings, not pointer tables).
                var printable = 0;
                for (var i = 0; i < windowLen; i++)
                {
                    var bb = code[startPos + i];
                    if (bb >= 0x20 && bb <= 0x7E)
                        printable++;
                }
                if (printable >= (int)(windowLen * 0.75))
                    return false;

                var considered = 0;
                var boundaryHits = 0;
                var inRangeAbs = 0;
                var inRangeRel = 0;
                var cands = new List<uint>(words);

                for (var w = 0; w < words; w++)
                {
                    var lo = code[startPos + (w * 2)];
                    var hi = code[startPos + (w * 2) + 1];
                    var val = (ushort)(lo | (hi << 8));
                    if (val == 0x0000 || val == 0xFFFF)
                        continue;

                    considered++;
                    var abs = (uint)val;
                    var rel = origin + abs;

                    var absOk = abs >= origin && abs < origin + (uint)code.Length;
                    var relOk = rel >= origin && rel < origin + (uint)code.Length;
                    if (absOk)
                        inRangeAbs++;
                    if (relOk)
                        inRangeRel++;

                    // Count as a strong hit if it lands on a decoded instruction boundary.
                    if (absOk && insByAddr.ContainsKey(abs))
                    {
                        boundaryHits++;
                        cands.Add(abs);
                    }
                    else if (relOk && insByAddr.ContainsKey(rel))
                    {
                        boundaryHits++;
                        cands.Add(rel);
                    }
                }

                if (considered < Math.Min(8, minWords))
                    return false;

                // Require most entries to look like in-image pointers.
                var inRangeScore = Math.Max(inRangeAbs, inRangeRel);
                if (inRangeScore < (int)(considered * 0.75))
                    return false;

                // Require a decent fraction to land on instruction boundaries.
                if (boundaryHits < Math.Max(minTargets, (int)(considered * 0.50)))
                    return false;

                // Extend while pointers remain mostly in-range.
                var len = words * 2;
                while (len + 2 <= maxLen)
                {
                    var lo = code[startPos + len];
                    var hi = code[startPos + len + 1];
                    var val = (ushort)(lo | (hi << 8));
                    if (val == 0x0000 || val == 0xFFFF)
                    {
                        len += 2;
                        continue;
                    }
                    var abs = (uint)val;
                    var rel = origin + abs;
                    var absOk = abs >= origin && abs < origin + (uint)code.Length;
                    var relOk = rel >= origin && rel < origin + (uint)code.Length;
                    if (!absOk && !relOk)
                        break;
                    len += 2;
                }

                byteLen = len;
                targets = cands.Distinct().OrderBy(x => x).ToList();
                return byteLen >= minByteLen && targets.Count >= minTargets;
            }

            bool TryDetectCodePointerTable(int startPos, out int byteLen, out List<uint> targets)
                => TryDetectCodePointerTableWithThresholds(startPos, minWords: 16, minTargets: 6, minByteLen: 32, out byteLen, out targets);

            static bool IsPrefixByte(byte b)
            {
                // Segment overrides: 2E CS, 36 SS, 3E DS, 26 ES
                // Rep: F2/F3
                // Operand/address size: 66/67 (rare in 16-bit but can exist)
                // Lock: F0
                return b is 0x2E or 0x36 or 0x3E or 0x26 or 0xF2 or 0xF3 or 0x66 or 0x67 or 0xF0;
            }

            static bool TryGetGroup5IndirectNearTargetDisp(Instruction ins, out bool isJmp, out ushort disp, out bool hasDisp, out bool hasIndexOrBase)
            {
                isJmp = false;
                disp = 0;
                hasDisp = false;
                hasIndexOrBase = false;

                var b = ins.Bytes;
                if (b == null || b.Length < 2)
                    return false;

                var i = 0;
                while (i < b.Length && IsPrefixByte(b[i]))
                    i++;

                if (i >= b.Length)
                    return false;

                if (b[i] != 0xFF)
                    return false;
                i++;
                if (i >= b.Length)
                    return false;

                var modrm = b[i++];
                var mod = (modrm >> 6) & 0x03;
                var reg = (modrm >> 3) & 0x07;
                var rm = modrm & 0x07;

                // Group 5: /2 = CALL r/m16, /4 = JMP r/m16
                if (reg != 2 && reg != 4)
                    return false;

                isJmp = reg == 4;

                // Ignore register-indirect (mod==3)
                if (mod == 3)
                    return false;

                // Roughly track if the addressing uses an index/base (vs absolute [disp16]).
                // 16-bit addressing rm encodings:
                // 0 [bx+si],1 [bx+di],2 [bp+si],3 [bp+di],4 [si],5 [di],6 [bp] (or disp16 if mod==0),7 [bx]
                hasIndexOrBase = !(mod == 0 && rm == 6);

                if (mod == 0 && rm == 6)
                {
                    // [disp16]
                    if (i + 1 >= b.Length)
                        return false;
                    disp = (ushort)(b[i] | (b[i + 1] << 8));
                    hasDisp = true;
                    return true;
                }

                if (mod == 1)
                {
                    // [.. + disp8]
                    if (i >= b.Length)
                        return false;
                    var d8 = unchecked((sbyte)b[i]);
                    disp = (ushort)(d8 < 0 ? (ushort)(0x10000 + d8) : (ushort)d8);
                    hasDisp = true;
                    return true;
                }

                if (mod == 2)
                {
                    // [.. + disp16]
                    if (i + 1 >= b.Length)
                        return false;
                    disp = (ushort)(b[i] | (b[i + 1] << 8));
                    hasDisp = true;
                    return true;
                }

                return false;
            }

            bool TryDetectCodePointerTableAtAddressWithThresholds(uint tableAddr, int minWords, int minTargets, int minByteLen, out int byteLen, out List<uint> targets)
            {
                byteLen = 0;
                targets = null;
                if (tableAddr < origin)
                    return false;
                var startPos = (int)(tableAddr - origin);
                if (startPos < 0 || startPos >= code.Length)
                    return false;
                return TryDetectCodePointerTableWithThresholds(startPos, minWords, minTargets, minByteLen, out byteLen, out targets);
            }

            // Best-effort reachability: walk relative branches/calls starting at origin.
            // This helps avoid applying data heuristics inside code, powers -BINMAP,
            // and acts as a guardrail against scanning text blobs as "code pointer tables".
            if (binInsights || masmCompatEmitCodeMap)
            {
                bool IsReturnOpcode(byte op) => op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA || op == 0xCF;

                bool IsStrongStringAddr(uint addr)
                {
                    if (!masmCompatEmitCodeMap || isStrongStringByte == null)
                        return false;
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    return isStrongStringByte[(int)(addr - origin)];
                }

                bool IsStrongFillAddr(uint addr)
                {
                    if (!masmCompatEmitCodeMap || isStrongFillByte == null)
                        return false;
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    return isStrongFillByte[(int)(addr - origin)];
                }

                bool IsStrongStrPtrTblAddr(uint addr)
                {
                    if (!masmCompatEmitCodeMap || isStrongStrPtrTblByte == null)
                        return false;
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    return isStrongStrPtrTblByte[(int)(addr - origin)];
                }

                bool IsStrongTagWordTblAddr(uint addr)
                {
                    if (!masmCompatEmitCodeMap || isStrongTagWordTblByte == null)
                        return false;
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    return isStrongTagWordTblByte[(int)(addr - origin)];
                }

                bool IsStrongDataAddr(uint addr) => IsStrongStringAddr(addr) || IsStrongFillAddr(addr) || IsStrongStrPtrTblAddr(addr) || IsStrongTagWordTblAddr(addr);

                bool RangeTouchesStrongString(uint start, int length)
                {
                    if (!masmCompatEmitCodeMap || isStrongStringByte == null)
                        return false;
                    if (length <= 0)
                        return false;
                    if (start < origin || start >= origin + (uint)code.Length)
                        return false;
                    var startPos = (int)(start - origin);
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                    {
                        if (isStrongStringByte[i])
                            return true;
                    }
                    return false;
                }

                bool RangeTouchesStrongFill(uint start, int length)
                {
                    if (!masmCompatEmitCodeMap || isStrongFillByte == null)
                        return false;
                    if (length <= 0)
                        return false;
                    if (start < origin || start >= origin + (uint)code.Length)
                        return false;
                    var startPos = (int)(start - origin);
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                    {
                        if (isStrongFillByte[i])
                            return true;
                    }
                    return false;
                }

                bool RangeTouchesStrongStrPtrTbl(uint start, int length)
                {
                    if (!masmCompatEmitCodeMap || isStrongStrPtrTblByte == null)
                        return false;
                    if (length <= 0)
                        return false;
                    if (start < origin || start >= origin + (uint)code.Length)
                        return false;
                    var startPos = (int)(start - origin);
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                    {
                        if (isStrongStrPtrTblByte[i])
                            return true;
                    }
                    return false;
                }

                bool RangeTouchesStrongTagWordTbl(uint start, int length)
                {
                    if (!masmCompatEmitCodeMap || isStrongTagWordTblByte == null)
                        return false;
                    if (length <= 0)
                        return false;
                    if (start < origin || start >= origin + (uint)code.Length)
                        return false;
                    var startPos = (int)(start - origin);
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                    {
                        if (isStrongTagWordTblByte[i])
                            return true;
                    }
                    return false;
                }

                bool TryGetRelBranchInfo16(Instruction ins, out uint target, out bool isCall, out bool isUnconditionalJmp)
                {
                    target = 0;
                    isCall = false;
                    isUnconditionalJmp = false;

                    var b = ins.Bytes;
                    if (b == null || b.Length == 0)
                        return false;

                    var op0 = b[0];
                    var next = (uint)ins.Offset + (uint)b.Length;

                    if (op0 == 0xE8 && b.Length >= 3)
                    {
                        var rel = (short)(b[1] | (b[2] << 8));
                        target = (uint)(next + (uint)rel);
                        isCall = true;
                        return true;
                    }

                    if (op0 == 0xE9 && b.Length >= 3)
                    {
                        var rel = (short)(b[1] | (b[2] << 8));
                        target = (uint)(next + (uint)rel);
                        isUnconditionalJmp = true;
                        return true;
                    }

                    if (op0 == 0xEB && b.Length >= 2)
                    {
                        var rel = unchecked((sbyte)b[1]);
                        target = (uint)(next + (uint)rel);
                        isUnconditionalJmp = true;
                        return true;
                    }

                    if ((op0 >= 0x70 && op0 <= 0x7F) && b.Length >= 2)
                    {
                        var rel = unchecked((sbyte)b[1]);
                        target = (uint)(next + (uint)rel);
                        return true;
                    }

                    if ((op0 == 0xE3 || op0 == 0xE0 || op0 == 0xE1 || op0 == 0xE2) && b.Length >= 2)
                    {
                        var rel = unchecked((sbyte)b[1]);
                        target = (uint)(next + (uint)rel);
                        return true;
                    }

                    if (op0 == 0x0F && b.Length >= 4)
                    {
                        var op1 = b[1];
                        if (op1 >= 0x80 && op1 <= 0x8F)
                        {
                            var rel = (short)(b[2] | (b[3] << 8));
                            target = (uint)(next + (uint)rel);
                            return true;
                        }
                    }

                    return false;
                }

                void WalkReachability(IEnumerable<uint> seeds)
                {
                    var pending = new Stack<uint>();
                    foreach (var s in seeds)
                        pending.Push(s);

                    static bool IsVeryLikelyDecodedData(string asmIns)
                    {
                        if (string.IsNullOrWhiteSpace(asmIns))
                            return true;

                        var s = asmIns.Trim().ToLowerInvariant();
                        if (s.StartsWith("invalid", StringComparison.Ordinal))
                            return true;

                        // Segment prefixes that don't exist in 8086-era code are a strong signal of misdecode.
                        if (s.Contains("fs:", StringComparison.Ordinal) || s.Contains("gs:", StringComparison.Ordinal))
                            return true;

                        // 32-bit reg tokens don't belong in BIN16 and are overwhelmingly decoded data.
                        if (Regex.IsMatch(s, @"\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b", RegexOptions.CultureInvariant))
                            return true;

                        // MMX/SSE register tokens are also a strong signal of decoded data.
                        if (Regex.IsMatch(s, @"\b(mm\d|xmm\d)\b", RegexOptions.CultureInvariant))
                            return true;

                        // System-call mnemonics are not expected in 16-bit DOS blobs.
                        if (s.StartsWith("sysret", StringComparison.Ordinal) || s.StartsWith("syscall", StringComparison.Ordinal) || s.StartsWith("sysexit", StringComparison.Ordinal))
                            return true;

                        // Far memory forms can be a formatter artifact from a wrong decode.
                        if (s.Contains(" far word ", StringComparison.Ordinal))
                            return true;

                        return false;
                    }

                    while (pending.Count > 0)
                    {
                        var a = pending.Pop();
                        if (IsStrongDataAddr(a))
                            continue;

                        if (!reachableInsAddrs.Add(a))
                            continue;

                        if (!insByAddr.TryGetValue(a, out var ins))
                            continue;

                        // If SharpDisasm produced an instruction text that is extremely likely decoded data,
                        // don't treat this as code and don't follow fallthrough into more garbage.
                        if (IsVeryLikelyDecodedData(ins.ToString()))
                        {
                            reachableInsAddrs.Remove(a);
                            continue;
                        }

                        var b = ins.Bytes ?? Array.Empty<byte>();
                        if (b.Length == 0)
                            continue;

                        var op0 = b[0];
                        var next = a + (uint)b.Length;

                        if (IsReturnOpcode(op0))
                            continue;

                        if (TryGetRelBranchInfo16(ins, out var target, out var isCall, out var isUncondJmp))
                        {
                            if (target >= origin && target < origin + (uint)code.Length && !IsStrongDataAddr(target))
                                pending.Push(target);

                            if (isCall)
                            {
                                if (next >= origin && next < origin + (uint)code.Length && !IsStrongDataAddr(next))
                                    pending.Push(next);
                            }
                            else if (!isUncondJmp)
                            {
                                if (next >= origin && next < origin + (uint)code.Length && !IsStrongDataAddr(next))
                                    pending.Push(next);
                            }

                            continue;
                        }

                        if (next >= origin && next < origin + (uint)code.Length && !IsStrongDataAddr(next))
                            pending.Push(next);
                    }
                }

                // Pass 1: find the obvious straight-line code.
                WalkReachability(new[] { origin });

                // Build a byte-level mask of reachable instruction bytes.
                // Important: reachableInsAddrs only tracks instruction *starts*, but table scans work on raw bytes.
                // Without a byte mask, a scan can start in the middle of a reachable instruction and produce false "codeptrtbl".
                bool[] reachableByte = null;
                if (masmCompatEmitCodeMap)
                {
                    reachableByte = new bool[code.Length];
                    foreach (var a in reachableInsAddrs)
                    {
                        if (a < origin || a >= origin + (uint)code.Length)
                            continue;
                        if (!insByAddr.TryGetValue(a, out var rin))
                            continue;
                        var rb = rin.Bytes ?? Array.Empty<byte>();
                        if (rb.Length == 0)
                            continue;
                        var startPos = (int)(a - origin);
                        var endPos = Math.Min(code.Length, startPos + rb.Length);
                        for (var i = startPos; i < endPos; i++)
                            reachableByte[i] = true;
                    }
                }

                bool IsReachableByteAddr(uint addr)
                {
                    if (!masmCompatEmitCodeMap || reachableByte == null)
                        return false;
                    if (addr < origin || addr >= origin + (uint)code.Length)
                        return false;
                    return reachableByte[(int)(addr - origin)];
                }

                bool RangeTouchesReachableBytes(uint start, int length)
                {
                    if (!masmCompatEmitCodeMap || reachableByte == null)
                        return false;
                    if (length <= 0)
                        return false;
                    if (start < origin || start >= origin + (uint)code.Length)
                        return false;
                    var startPos = (int)(start - origin);
                    var endPos = Math.Min(code.Length, startPos + length);
                    for (var i = startPos; i < endPos; i++)
                    {
                        if (reachableByte[i])
                            return true;
                    }
                    return false;
                }

                // Anchor jump-table discovery on *reachable* indirect JMP/CALL sites.
                // This is more reliable than scanning the whole binary for "pointer-ish" words.
                if (masmCompatEmitCodeMap)
                {
                    foreach (var ins in instructions)
                    {
                        var insAddr = (uint)ins.Offset;
                        if (!reachableInsAddrs.Contains(insAddr))
                            continue;

                        if (!TryGetGroup5IndirectNearTargetDisp(ins, out var isJmp, out var disp, out var hasDisp, out var hasIndexOrBase))
                            continue;
                        if (!hasDisp)
                            continue;

                        if (isJmp)
                            indirectJmpCount++;
                        else
                            indirectCallCount++;

                        // Candidate table addresses: disp can be absolute (segment offset) or file-relative (origin+disp).
                        var candAbs = (uint)disp;
                        var candRel = origin + (uint)disp;

                        foreach (var cand in new[] { candAbs, candRel }.Distinct())
                        {
                            if (cand < origin || cand >= origin + (uint)code.Length)
                                continue;
                            if (reachableInsAddrs.Contains(cand) || IsReachableByteAddr(cand))
                                continue;
                            if (IsStrongDataAddr(cand))
                                continue;

                            // Anchored tables are allowed to be smaller than scan-detected ones.
                            if (TryDetectCodePointerTableAtAddressWithThresholds(cand, minWords: 6, minTargets: 4, minByteLen: 12, out var tblLen, out var tgts))
                            {
                                if (RangeTouchesStrongString(cand, tblLen))
                                    continue;
                                if (RangeTouchesStrongFill(cand, tblLen))
                                    continue;
                                if (RangeTouchesStrongStrPtrTbl(cand, tblLen))
                                    continue;
                                if (RangeTouchesStrongTagWordTbl(cand, tblLen))
                                    continue;
                                if (RangeTouchesReachableBytes(cand, tblLen))
                                    continue;

                                var newTargets = tgts
                                    .Where(t => !reachableInsAddrs.Contains(t) && !IsStrongDataAddr(t) && !IsReachableByteAddr(t))
                                    .Distinct()
                                    .OrderBy(t => t)
                                    .ToList();

                                // If a "table" mostly points at already-reachable code, it's probably not a dispatch table.
                                if (newTargets.Count < 2)
                                    continue;

                                jumpTableAnchors.Add((insAddr, cand, isJmp ? "ijmp" : "icall"));
                                RecordDataRegion(cand, tblLen, "codeptrtbl", $"anchor: {(isJmp ? "indirect jmp" : "indirect call")} @ {insAddr:X5}h");
                                foreach (var t in newTargets)
                                    extraEntryPoints.Add(t);
                            }
                        }
                    }

                    // Optional: broad scan for code pointer tables to discover extra entrypoints (jump tables, dispatch tables).
                    // Only scan areas that are not already reachable code and not inside strong-string regions.
                    if (extraEntryPoints.Count < 8)
                    {
                        for (var p = 0; p + 32 <= code.Length; p += 2)
                        {
                            var addr = origin + (uint)p;
                            if (reachableInsAddrs.Contains(addr) || (reachableByte != null && reachableByte[p]))
                                continue;
                            if (IsStrongDataAddr(addr))
                                continue;

                            if (TryDetectCodePointerTable(p, out var tblLen, out var targets))
                            {
                                if (RangeTouchesStrongString(addr, tblLen))
                                    continue;
                                if (RangeTouchesStrongFill(addr, tblLen))
                                    continue;
                                if (RangeTouchesStrongStrPtrTbl(addr, tblLen))
                                    continue;
                                if (RangeTouchesStrongTagWordTbl(addr, tblLen))
                                    continue;
                                if (RangeTouchesReachableBytes(addr, tblLen))
                                    continue;

                                var newTargets = targets
                                    .Where(t => !reachableInsAddrs.Contains(t) && !IsStrongDataAddr(t) && !IsReachableByteAddr(t))
                                    .Distinct()
                                    .OrderBy(t => t)
                                    .ToList();

                                if (newTargets.Count < 2)
                                    continue;

                                RecordDataRegion(addr, tblLen, "codeptrtbl", "scan: word table of code pointers (jump/dispatch table candidate)");
                                foreach (var t in newTargets)
                                    extraEntryPoints.Add(t);
                                p += Math.Max(0, tblLen - 2);
                            }
                        }
                    }
                }

                // Pass 2: incorporate code discovered via jump/dispatch tables.
                if (masmCompatEmitCodeMap && extraEntryPoints.Count > 0)
                    WalkReachability(extraEntryPoints.OrderBy(x => x));
            }

            var hexRe = binInsights && stringsByAddr != null && stringsByAddr.Count > 0
                ? new Regex(@"0x[0-9a-fA-F]+|\b[0-9a-fA-F]{3,6}h\b", RegexOptions.Compiled)
                : null;

            if (binInsights && hexRe != null)
            {
                foreach (var ins in instructions)
                {
                    var insText = ins.ToString();

                    // Avoid annotating control-flow instructions (branch targets often alias string addresses).
                    var mnemonicTok = insText.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault() ?? string.Empty;

                    var afterMnemonic = insText.Length > mnemonicTok.Length
                        ? insText.Substring(mnemonicTok.Length).TrimStart()
                        : string.Empty;

                    var isPointery = mnemonicTok.Equals("mov", StringComparison.OrdinalIgnoreCase) ||
                                    mnemonicTok.Equals("lea", StringComparison.OrdinalIgnoreCase) ||
                                    mnemonicTok.Equals("push", StringComparison.OrdinalIgnoreCase);

                    if (mnemonicTok.Equals("mov", StringComparison.OrdinalIgnoreCase) && afterMnemonic.StartsWith("[", StringComparison.Ordinal))
                        isPointery = false;

                    if (!isPointery || mnemonicTok.StartsWith("j", StringComparison.OrdinalIgnoreCase) ||
                        mnemonicTok.Equals("call", StringComparison.OrdinalIgnoreCase) ||
                        mnemonicTok.StartsWith("ret", StringComparison.OrdinalIgnoreCase))
                        continue;

                    foreach (Match m in hexRe.Matches(insText))
                    {
                        if (!TryParseAddressToken(m.Value, out var tokVal))
                            continue;

                        if (stringsByAddr.TryGetValue(tokVal, out _))
                        {
                            referencedStringAddrs.Add(tokVal);
                            break;
                        }
                    }
                }
            }

            // Additional best-effort: many games reference text via pointer tables, not direct immediates.
            // If we can spot word tables that point at detected strings, treat those string addresses as referenced
            // so inline string carving can kick in.
            if (binInsights && emitInlineStringLabels && stringsByAddr != null && stringsByAddr.Count > 0)
            {
                bool TryDetectStringPointerTable(int startPos, out int byteLen, out bool relative)
                {
                    byteLen = 0;
                    relative = false;
                    if (startPos < 0 || startPos + 32 > code.Length)
                        return false;

                    // Word tables are typically even-aligned.
                    var a = origin + (uint)startPos;
                    if ((a & 1) != 0)
                        return false;

                    var windowLen = 64;
                    if (startPos + windowLen > code.Length)
                        windowLen = code.Length - startPos;
                    if (windowLen < 32)
                        return false;

                    var words = windowLen / 2;
                    var absHits = 0;
                    var relHits = 0;
                    var considered = 0;

                    for (var w = 0; w < words; w++)
                    {
                        var lo = code[startPos + (w * 2)];
                        var hi = code[startPos + (w * 2) + 1];
                        var val = (ushort)(lo | (hi << 8));
                        if (val == 0x0000 || val == 0xFFFF)
                            continue;
                        considered++;

                        var abs = (uint)val;
                        var rel = origin + abs;
                        if (stringsByAddr.ContainsKey(abs))
                            absHits++;
                        if (stringsByAddr.ContainsKey(rel))
                            relHits++;
                    }

                    if (considered < 8)
                        return false;

                    // Require a decent density of string pointers.
                    var best = Math.Max(absHits, relHits);
                    if (best < 6 || best < (int)(considered * 0.50))
                        return false;

                    relative = relHits > absHits;

                    // Extend while entries keep pointing at strings (allowing occasional 0/FFFF).
                    var len = words * 2;
                    while (startPos + len + 2 <= code.Length && len < 512)
                    {
                        var lo = code[startPos + len];
                        var hi = code[startPos + len + 1];
                        var val = (ushort)(lo | (hi << 8));
                        if (val == 0x0000 || val == 0xFFFF)
                        {
                            len += 2;
                            continue;
                        }

                        var abs = (uint)val;
                        var tgt = relative ? (origin + abs) : abs;
                        if (!stringsByAddr.ContainsKey(tgt))
                            break;

                        len += 2;
                    }

                    byteLen = len;
                    return byteLen >= 32;
                }

                for (var p = 0; p + 32 <= code.Length;)
                {
                    if (TryDetectStringPointerTable(p, out var tblLen, out var relMode))
                    {
                        var words = tblLen / 2;
                        for (var w = 0; w < words; w++)
                        {
                            var lo = code[p + (w * 2)];
                            var hi = code[p + (w * 2) + 1];
                            var val = (ushort)(lo | (hi << 8));
                            if (val == 0x0000 || val == 0xFFFF)
                                continue;
                            var abs = (uint)val;
                            var tgt = relMode ? (origin + abs) : abs;
                            if (stringsByAddr.ContainsKey(tgt))
                                referencedStringAddrs.Add(tgt);
                        }

                        p += tblLen;
                        continue;
                    }

                    p += 2;
                }

            }

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (flat 16-bit binary)");
            sb.AppendLine($"; Origin: {(masmCompat ? ToMasmHexU32(origin, 4) : $"0x{origin:X}")}");
            sb.AppendLine($"; Bytes: {(masmCompat ? ToMasmHexU32NoPad((uint)maxBytes) : $"0x{maxBytes:X}")} ({maxBytes})");
            sb.AppendLine(";");

            if (masmCompat)
            {
                sb.AppendLine(masmCompatEmitInstructions ? ".686" : ".8086");
                sb.AppendLine(".model tiny");
                sb.AppendLine(".code");
                // In byte-perfect db+mnemonic-comment mode, we still *decode* using the provided logical origin
                // (COM-style default 0100h), but we must emit `org 0000h` so WLINK `format raw bin` does not
                // prepend a 256-byte zero pad region.
                var asmOrg = (masmCompatEmitInstructionComments && !masmCompatEmitInstructions) ? 0u : origin;
                var asmOrgText = asmOrg == 0 ? "0000h" : ToMasmHexU32(asmOrg, 4);
                sb.AppendLine($"org {asmOrgText}");
                if (asmOrg != origin)
                    sb.AppendLine($"; logical origin: {ToMasmHexU32(origin, 4)}");
                sb.AppendLine("start:");
                sb.AppendLine();
            }

            if (binInsights && stringsByAddr != null && stringsByAddr.Count > 0)
            {
                sb.AppendLine($"; Strings (best-effort) | referenced: {referencedStringAddrs.Count} | detected: {stringsByAddr.Count}");
                foreach (var kvp in stringsByAddr.OrderBy(k => k.Key).Take(256))
                {
                    var note = referencedStringAddrs.Contains(kvp.Key)
                        ? string.Empty
                        : " (detected, not referenced)";

                    if (masmCompat)
                    {
                        // In MASM/WASM mode we emit inline `str_XXXX:` labels for referenced strings.
                        // Emitting `str_XXXX EQU ...` too would redefine the symbol and can trigger WASM E036.
                        var preview = kvp.Value.Preview.Replace("\"", "'");
                        sb.AppendLine($"; str_{kvp.Key:X4} = {ToMasmHexU32(kvp.Key, 4)} ; '{preview}'{note}");
                    }
                    else
                    {
                        sb.AppendLine($"str_{kvp.Key:X4} EQU 0x{kvp.Key:X} ; \"{kvp.Value.Preview}\"{note}");
                    }
                }
                sb.AppendLine(";");
            }

            if (!masmCompat)
            {
                sb.AppendLine("; OFFSET BYTES DISASSEMBLY");
                sb.AppendLine(";-------------------------------------------");
            }

            // Build carve regions (only referenced strings) and clamp to the disassembly window.
            // Note: we deliberately allow carving to start at any address, even if it is not aligned
            // to a decoded instruction boundary; in that case we emit db bytes to resync.
            var carveByAddr = new Dictionary<uint, BinString>();
            if (binInsights && emitInlineStringLabels && stringsByAddr != null && referencedStringAddrs.Count > 0)
            {
                foreach (var a in referencedStringAddrs)
                {
                    if (!stringsByAddr.TryGetValue(a, out var s))
                        continue;

                    // Never carve out over control-flow labels.
                    if (functionStarts.Contains(a) || labelTargets.Contains(a))
                        continue;

                    if (a < origin)
                        continue;

                    var maxAddr = origin + (uint)maxBytes;
                    if (a >= maxAddr)
                        continue;

                    // Clamp length to available bytes.
                    var remaining = (int)(maxAddr - a);
                    var len = Math.Max(0, Math.Min(s.Length, remaining));
                    if (len < 1)
                        continue;

                    carveByAddr[a] = new BinString(a, len, s.Preview);
                }
            }

            var carveStarts = carveByAddr.Keys.OrderBy(x => x).ToList();
            var nextCarveIndex = 0;

            uint NextCarveStart()
            {
                if (nextCarveIndex < carveStarts.Count)
                    return carveStarts[nextCarveIndex];
                return uint.MaxValue;
            }

            static string EscapeDbString(string s, bool masm)
            {
                if (s == null)
                    return string.Empty;

                // MASM/WASM string literals escape quotes by doubling them.
                if (masm)
                    return s.Replace("\"", "\"\"");

                return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
            }

            void EmitDbBytes(uint addr, int count)
            {
                var pos = checked((int)(addr - origin));
                var remaining = Math.Min(count, code.Length - pos);
                var curAddr = addr;

                while (remaining > 0)
                {
                    var take = Math.Min(16, remaining);
                    var slice = code.AsSpan(pos, take);
                    var bytesHex = string.Concat(slice.ToArray().Select(b => b.ToString("X2")));
                    if (masmCompat)
                    {
                        var dbArgs = string.Join(",", slice.ToArray().Select(ToMasmHexByte));
                        sb.AppendLine($"db {dbArgs} ; {curAddr:X8}h {bytesHex}");
                    }
                    else
                    {
                        var dbArgs = string.Join(", ", slice.ToArray().Select(b => $"0x{b:X2}"));
                        sb.AppendLine($"{curAddr:X8}h {bytesHex,-16} db {dbArgs}");
                    }

                    pos += take;
                    curAddr += (uint)take;
                    remaining -= take;
                }
            }

            void EmitStringBlock(BinString s)
            {
                // Emit label and db lines (chunked) with a hex bytes column.
                // Bytes are guaranteed printable by ScanStrings.
                var pos = checked((int)(s.Address - origin));
                var remaining = Math.Min(s.Length, code.Length - pos);
                var curAddr = s.Address;

                sb.AppendLine($"str_{s.Address:X4}:");
                RecordDataRegion(s.Address, s.Length, "string", "carved referenced string");

                while (remaining > 0)
                {
                    var take = Math.Min(16, remaining);
                    var slice = code.AsSpan(pos, take);
                    var bytesHex = string.Concat(slice.ToArray().Select(b => b.ToString("X2")));
                    var ascii = Encoding.ASCII.GetString(slice);
                    if (masmCompat)
                    {
                        // Avoid db "..." string literals in WASM: emit raw bytes and keep ASCII only in comment.
                        var dbArgs = string.Join(",", slice.ToArray().Select(ToMasmHexByte));
                        var preview = ascii.Replace("\r", " ").Replace("\n", " ");
                        sb.AppendLine($"db {dbArgs} ; {curAddr:X8}h {bytesHex} | {preview}");
                    }
                    else
                    {
                        var escaped = EscapeDbString(ascii, masm: false);
                        sb.AppendLine($"{curAddr:X8}h {bytesHex,-16} db \"{escaped}\"");
                    }

                    pos += take;
                    curAddr += (uint)take;
                    remaining -= take;
                }
            }

            bool TryGetFillRun(int startPos, out byte value, out int length)
            {
                value = 0;
                length = 0;
                if (startPos < 0 || startPos >= code.Length)
                    return false;

                value = code[startPos];
                // Common padding/fill bytes.
                if (value != 0x00 && value != 0xFF && value != 0x90)
                    return false;

                var i = startPos;
                while (i < code.Length && code[i] == value)
                    i++;

                length = i - startPos;
                return length >= 16;
            }

            bool TryDetectWordPointerTable(int startPos, out int byteLen)
            {
                byteLen = 0;
                if (startPos < 0 || startPos + 32 > code.Length)
                    return false;

                // Word tables are typically even-aligned.
                var a = origin + (uint)startPos;
                if ((a & 1) != 0)
                    return false;

                // Require at least 16 words (32 bytes) and allow extension.
                var maxLen = Math.Min(256, code.Length - startPos);
                var windowLen = Math.Min(64, maxLen);
                var words = windowLen / 2;
                if (words < 16)
                    return false;

                // Reject ASCII-heavy regions (very likely text / strings, not pointer tables).
                var printable = 0;
                for (var i = 0; i < windowLen; i++)
                {
                    var bb = code[startPos + i];
                    if (bb >= 0x20 && bb <= 0x7E)
                        printable++;
                }
                if (printable >= (int)(windowLen * 0.75))
                    return false;

                var inRangeAbs = 0;
                var inRangeRel = 0;
                var labelHits = 0;
                var considered = 0;
                var lowByteCounts = new Dictionary<byte, int>();
                for (var w = 0; w < words; w++)
                {
                    var lo = code[startPos + (w * 2)];
                    var hi = code[startPos + (w * 2) + 1];
                    var val = (ushort)(lo | (hi << 8));

                    // Skip null/sentinel entries for scoring; many tables include these.
                    if (val == 0x0000 || val == 0xFFFF)
                        continue;

                    considered++;

                    var loByte = (byte)(val & 0xFF);
                    lowByteCounts.TryGetValue(loByte, out var c);
                    lowByteCounts[loByte] = c + 1;

                    var abs = (uint)val;
                    if (abs >= origin && abs < origin + (uint)code.Length)
                        inRangeAbs++;

                    // Also consider offsets that are file-relative (origin + val).
                    var rel = origin + abs;
                    if (rel >= origin && rel < origin + (uint)code.Length)
                        inRangeRel++;

                    if (labelByAddr.ContainsKey(abs) || labelByAddr.ContainsKey(rel) || (stringsByAddr != null && (stringsByAddr.ContainsKey(abs) || stringsByAddr.ContainsKey(rel))))
                        labelHits++;
                }

                if (considered < 8)
                    return false;

                // Reject tables where a non-zero low byte dominates (often indicates packed word data, not addresses).
                if (lowByteCounts.Count > 0)
                {
                    var top = lowByteCounts.OrderByDescending(kvp => kvp.Value).First();
                    if (top.Key != 0x00 && top.Value >= (int)(considered * 0.70))
                        return false;
                }

                var score = Math.Max(inRangeAbs, inRangeRel);
                // If at least 75% of entries look like in-image pointers, treat it as a table.
                if (score < (int)(considered * 0.75))
                    return false;

                // Require at least a few entries to map to known labels/strings to reduce false positives on code.
                if (labelHits < Math.Max(4, (int)(considered * 0.40)))
                    return false;

                // Extend while the pattern holds.
                var len = words * 2;
                while (len + 2 <= maxLen)
                {
                    var lo = code[startPos + len];
                    var hi = code[startPos + len + 1];
                    var val = (ushort)(lo | (hi << 8));
                    var abs = (uint)val;
                    var absOk = abs >= origin && abs < origin + (uint)code.Length;
                    var relOk = (origin + abs) >= origin && (origin + abs) < origin + (uint)code.Length;
                    if (!absOk && !relOk)
                        break;
                    len += 2;
                }

                byteLen = len;
                return byteLen >= 32;
            }

            bool TryDetectWordDataTable(int startPos, out int byteLen, out bool looksLikeBitmap)
            {
                byteLen = 0;
                looksLikeBitmap = false;
                if (startPos < 0 || startPos + 32 > code.Length)
                    return false;

                // Word tables are typically even-aligned.
                var a = origin + (uint)startPos;
                if ((a & 1) != 0)
                    return false;

                var maxLen = Math.Min(256, code.Length - startPos);
                var windowLen = Math.Min(64, maxLen);

                // Reject ASCII-heavy regions (very likely text blocks, not numeric tables).
                var printable = 0;
                for (var i = 0; i < windowLen; i++)
                {
                    var bb = code[startPos + i];
                    if (bb >= 0x20 && bb <= 0x7E)
                        printable++;
                }
                if (printable >= (int)(windowLen * 0.70))
                    return false;

                // Bit-pattern heavy blocks often represent packed sprite/bitmap/tile data.
                var patternBytes = 0;
                for (var i = 0; i < windowLen; i++)
                {
                    var bb = code[startPos + i];
                    if (bb == 0x00 || bb == 0xFF || bb == 0xAA || bb == 0x55 || bb == 0x33 || bb == 0xCC || bb == 0xF0 || bb == 0x0F)
                        patternBytes++;
                }
                looksLikeBitmap = patternBytes >= (int)(windowLen * 0.50);

                // Heuristic: if disassembling here produces a bunch of tiny/odd instructions, it's likely data.
                if (insByAddr.TryGetValue(a, out var ins) && (ins.Bytes?.Length ?? 0) >= 4)
                    return false;

                // Extend while not crossing boundaries and still not ASCII-heavy.
                var len = 32;
                while (len + 16 <= maxLen)
                {
                    var chunkLen = Math.Min(64, len + 16);
                    var p = 0;
                    for (var i = 0; i < chunkLen; i++)
                    {
                        var bb = code[startPos + i];
                        if (bb >= 0x20 && bb <= 0x7E)
                            p++;
                    }
                    if (p >= (int)(chunkLen * 0.50))
                        break;
                    len += 16;
                }

                byteLen = len;
                return byteLen >= 32;
            }

            void EmitWordTable(uint addr, int byteLen, string labelPrefix, string comment, bool rewritePointers)
            {
                sb.AppendLine();
                sb.AppendLine($"{labelPrefix}_{addr:X5}: ; heuristic: {comment}");

                // In MASM/WASM-compatible mode, keep output always-assemblable.
                // DW tables can trip WASM into interpreting small constants as offsets; emit raw bytes instead.
                if (masmCompat)
                {
                    EmitDbBytes(addr, byteLen);
                    return;
                }

                var pos = checked((int)(addr - origin));
                var remaining = Math.Min(byteLen, code.Length - pos);
                var curAddr = addr;
                while (remaining > 0)
                {
                    var takeBytes = Math.Min(16, remaining); // 8 words per line
                    takeBytes = takeBytes & ~1; // keep even
                    if (takeBytes <= 0)
                        break;

                    var slice = code.AsSpan(pos, takeBytes);
                    var bytesHex = string.Concat(slice.ToArray().Select(b => b.ToString("X2")));

                    var items = new List<string>(takeBytes / 2);
                    for (var i = 0; i < takeBytes; i += 2)
                    {
                        var val = (ushort)(slice[i] | (slice[i + 1] << 8));
                        if (rewritePointers)
                        {
                            var abs = (uint)val;
                            var cand1 = abs;
                            var cand2 = origin + abs;

                            string label = null;
                            if (labelByAddr.TryGetValue(cand1, out var l1))
                                label = l1;
                            else if (labelByAddr.TryGetValue(cand2, out var l2))
                                label = l2;
                            else if (stringsByAddr != null && stringsByAddr.ContainsKey(cand1))
                                label = $"str_{cand1:X4}";
                            else if (stringsByAddr != null && stringsByAddr.ContainsKey(cand2))
                                label = $"str_{cand2:X4}";

                            items.Add(label ?? $"0x{val:X4}");
                        }
                        else
                        {
                            items.Add($"0x{val:X4}");
                        }
                    }

                    sb.AppendLine($"{curAddr:X8}h {bytesHex,-16} dw {string.Join(", ", items)}");

                    pos += takeBytes;
                    curAddr += (uint)takeBytes;
                    remaining -= takeBytes;
                }
            }

            bool TryDetectLowEntropy(int startPos, out int byteLen)
            {
                byteLen = 0;
                if (startPos < 0 || startPos + 64 > code.Length)
                    return false;

                var maxLen = Math.Min(256, code.Length - startPos);
                var len = 64;

                // Grow in 32-byte steps while unique-byte count stays small.
                while (len + 32 <= maxLen)
                {
                    var set = new HashSet<byte>();
                    for (var i = 0; i < len + 32; i++)
                        set.Add(code[startPos + i]);

                    if (set.Count <= 4)
                        len += 32;
                    else
                        break;
                }

                // Final check for current len.
                {
                    var set = new HashSet<byte>();
                    for (var i = 0; i < len; i++)
                        set.Add(code[startPos + i]);
                    if (set.Count > 4)
                        return false;
                }

                byteLen = len;
                return byteLen >= 64;
            }

            static int? GuessRepeatingRowWidth(ReadOnlySpan<byte> data)
            {
                // Best-effort: guess a repeating row width for bitmap/tile-like blocks.
                // We try common row widths and use a simple autocorrelation-by-shift score:
                // count matches where data[i] == data[i + width].
                if (data.Length < 64)
                    return null;

                var candidates = new[] { 8, 16, 24, 32, 40, 48, 64 };
                var bestWidth = 0;
                var bestScore = -1.0;

                foreach (var width in candidates)
                {
                    if (width <= 0 || width > data.Length)
                        continue;

                    if ((data.Length / width) < 4)
                        continue;

                    var limit = data.Length - width;
                    if (limit <= 0)
                        continue;

                    var matches = 0;
                    // Cap work; we don't need the entire block to decide.
                    var sample = Math.Min(limit, 2048);
                    for (var i = 0; i < sample; i++)
                    {
                        if (data[i] == data[i + width])
                            matches++;
                    }

                    var score = (double)matches / sample;
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestWidth = width;
                    }
                }

                if (bestWidth <= 0)
                    return null;

                // Require a minimum correlation; random data is ~1/256.
                // For sprites/tiles with background and repeated structure, this tends to be noticeably higher.
                if (bestScore >= 0.18)
                    return bestWidth;

                return null;
            }

            static bool TryDetectLenPrefixedTextBlock(byte[] bytes, int start, int maxLen, out int byteLen, out List<(uint addr, int len, string preview)> segments)
            {
                byteLen = 0;
                segments = null;

                if (bytes == null || start < 0 || start >= bytes.Length)
                    return false;
                if (maxLen <= 0)
                    return false;

                // Format (best-effort, observed in Decathlon):
                //   03 <len> <len bytes payload> 00 03 <len> ... 00 ...
                // Payload is usually ASCII with a few token bytes >= 80h.
                var i = start;
                var end = Math.Min(bytes.Length, start + maxLen);
                var found = new List<(uint addr, int len, string preview)>();

                // Allow a small NUL prefix before the first 03 <len> segment.
                var prefix = 0;
                while (i < end && bytes[i] == 0x00 && prefix < 8)
                {
                    i++;
                    prefix++;
                }

                while (i + 2 <= end)
                {
                    if (bytes[i] != 0x03)
                        break;
                    if (i + 2 > end)
                        break;

                    var len = bytes[i + 1];
                    // Keep this conservative; long blocks are handled via multiple segments.
                    if (len == 0 || len > 160)
                        break;

                    var payloadStart = i + 2;
                    var payloadEnd = payloadStart + len;
                    if (payloadEnd > end)
                        break;

                    // Reject if payload contains NULs; those are more likely binary tables.
                    var printableOrToken = 0;
                    var weird = 0;
                    var sbPreview = new StringBuilder(len);
                    for (var j = payloadStart; j < payloadEnd; j++)
                    {
                        var b = bytes[j];
                        if (b == 0x00)
                        {
                            weird += 10;
                            sbPreview.Append("<00>");
                            continue;
                        }

                        if (b >= 0x20 && b <= 0x7E)
                        {
                            printableOrToken++;
                            sbPreview.Append((char)b);
                        }
                        else if (b == 0x0D)
                        {
                            printableOrToken++;
                            sbPreview.Append("\\r");
                        }
                        else if (b == 0x0A)
                        {
                            printableOrToken++;
                            sbPreview.Append("\\n");
                        }
                        else if (b >= 0x80)
                        {
                            // Treat high-bit bytes as in-band tokens (e.g. special key glyphs).
                            printableOrToken++;
                            sbPreview.Append($"<{b:X2}>");
                        }
                        else
                        {
                            weird++;
                            sbPreview.Append($"<{b:X2}>");
                        }
                    }

                    // Require mostly readable payload and low weirdness.
                    if (printableOrToken < Math.Max(4, (int)(len * 0.70)) || weird > 6)
                        break;

                    found.Add((0, len, sbPreview.ToString()));
                    i = payloadEnd;

                    // Optional separator NUL(s) between segments.
                    var nulCount = 0;
                    while (i < end && bytes[i] == 0x00 && nulCount < 8)
                    {
                        i++;
                        nulCount++;
                    }

                    // Next segment must start with 03, otherwise end block.
                    if (i >= end || bytes[i] != 0x03)
                        break;
                }

                if (found.Count < 3)
                    return false;

                var totalLen = i - start;
                if (totalLen < 24)
                    return false;

                byteLen = totalLen;
                segments = found;
                return true;
            }

            var posInCode = 0;

            while (posInCode < code.Length)
            {
                var addr = origin + (uint)posInCode;
                var nextCarveStart = NextCarveStart();

                // If we are at (or beyond) a carve point, emit it and continue.
                if (addr == nextCarveStart && carveByAddr.TryGetValue(addr, out var carveStr))
                {
                    sb.AppendLine();
                    EmitStringBlock(carveStr);
                    posInCode += carveStr.Length;
                    nextCarveIndex++;
                    continue;
                }

                // Emit labels (functions/locs) if any.
                if (binInsights)
                {
                    if (functionStarts.Contains(addr))
                    {
                        sb.AppendLine();
                        sb.Append($"func_{addr:X5}:");
                        if (callXrefs.TryGetValue(addr, out var callers) && callers.Count > 0)
                        {
                            var xs = string.Join(", ", callers.Distinct().OrderBy(x => x).Take(8)
                                .Select(x => masmCompat ? ToMasmHexU32(x, 4) : $"0x{x:X}"));
                            sb.AppendLine($" ; XREF: called from {xs}");
                        }
                        else
                        {
                            sb.AppendLine();
                        }
                    }
                    else if (labelTargets.Contains(addr))
                    {
                        sb.Append($"loc_{addr:X5}:");
                        if (jumpXrefs.TryGetValue(addr, out var sources) && sources.Count > 0)
                        {
                            var xs = string.Join(", ", sources.Distinct().OrderBy(x => x).Take(8)
                                .Select(x => masmCompat ? ToMasmHexU32(x, 4) : $"0x{x:X}"));
                            sb.AppendLine($" ; XREF: jmp/jcc from {xs}");
                        }
                        else
                        {
                            sb.AppendLine();
                        }
                    }
                }
                else if (emitAsmLabels && labelTargets.Contains(addr))
                {
                    sb.AppendLine();
                    sb.AppendLine($"loc_{addr:X5}:");
                }

                // Data heuristics (only when insights enabled, and only if this address isn't a known control-flow target).
                if (binInsights && !functionStarts.Contains(addr) && !labelTargets.Contains(addr))
                {
                    var clampLimit = nextCarveStart != uint.MaxValue && nextCarveStart > addr
                        ? (int)Math.Min(int.MaxValue, nextCarveStart - addr)
                        : int.MaxValue;

                    // Decathlon-style text resources often appear as 03 <len> <payload> 00 ... blocks.
                    if (TryDetectLenPrefixedTextBlock(code, posInCode, clampLimit, out var msgLen, out var msgSegments))
                    {
                        sb.AppendLine();
                        sb.AppendLine($"msgblk_{addr:X5}: ; heuristic: len-prefixed text block segments={msgSegments.Count} bytes={msgLen}");
                        var segAddr = addr;
                        var cursor = posInCode;

                        // Skip the same small NUL prefix the detector allows.
                        var prefix = 0;
                        while (cursor < code.Length && code[cursor] == 0x00 && prefix < 8)
                        {
                            cursor++;
                            segAddr++;
                            prefix++;
                        }

                        foreach (var seg in msgSegments)
                        {
                            if (cursor + 2 > code.Length)
                                break;
                            if (code[cursor] != 0x03)
                                break;
                            var len = code[cursor + 1];
                            var preview = seg.preview;
                            if (preview.Length > 80)
                                preview = preview.Substring(0, 80) + "...";
                            var previewSafe = preview.Replace("\"", "'");
                            sb.AppendLine($";   msg @{segAddr:X5} len={len:X2} \"{previewSafe}\"");

                            segAddr += (uint)(2 + len);
                            cursor += (2 + len);
                            // account for NUL separators (same bound as in detection)
                            var nulCount = 0;
                            while (cursor < code.Length && code[cursor] == 0x00 && nulCount < 8)
                            {
                                segAddr += 1;
                                cursor += 1;
                                nulCount++;
                            }
                        }

                        EmitDbBytes(addr, msgLen);
                        RecordDataRegion(addr, msgLen, "text", "heuristic: len-prefixed text block");
                        posInCode += msgLen;
                        continue;
                    }

                    // The remaining heuristics are more speculative; avoid overriding addresses already marked reachable.
                    if (reachableInsAddrs.Count != 0 && reachableInsAddrs.Contains(addr))
                    {
                        // Fall through to instruction decoding.
                    }
                    else
                    {

                        if (TryGetFillRun(posInCode, out var fillVal, out var fillLen))
                        {
                            fillLen = Math.Min(fillLen, clampLimit);
                            sb.AppendLine($"; heuristic: padding/fill {(masmCompat ? ToMasmHexByte(fillVal) : $"0x{fillVal:X2}")} x{fillLen}");
                            EmitDbBytes(addr, fillLen);
                            RecordDataRegion(addr, fillLen, "fill", $"heuristic: fill {fillVal:X2}h x{fillLen}");
                            posInCode += fillLen;
                            continue;
                        }

                    if (TryDetectWordPointerTable(posInCode, out var tableLen))
                    {
                        tableLen = Math.Min(tableLen, clampLimit);
                        if (tableLen >= 32)
                        {
                            EmitWordTable(addr, tableLen, "tblp", "16-bit pointer table", rewritePointers: true);
                            RecordDataRegion(addr, tableLen, "table", "heuristic: 16-bit pointer table");
                            posInCode += tableLen;
                            continue;
                        }
                    }

                    if (TryDetectWordDataTable(posInCode, out var wordLen, out var looksLikeBmp))
                    {
                        wordLen = Math.Min(wordLen, clampLimit);
                        if (wordLen >= 32)
                        {
                            string cmt;
                            if (looksLikeBmp)
                            {
                                var span = code.AsSpan(posInCode, Math.Min(wordLen, code.Length - posInCode));
                                var rowW = GuessRepeatingRowWidth(span);
                                cmt = rowW.HasValue
                                    ? $"16-bit word table (bit-pattern heavy; likely sprite/bitmap/tile data) rowsize={rowW.Value}B width~{rowW.Value * 8}px@1bpp/{rowW.Value * 4}px@2bpp/{rowW.Value * 2}px@4bpp rows~{Math.Max(1, wordLen / rowW.Value)}"
                                    : "16-bit word table (bit-pattern heavy; likely sprite/bitmap/tile data)";
                            }
                            else
                            {
                                cmt = "16-bit word table";
                            }
                            EmitWordTable(addr, wordLen, "tblw", cmt, rewritePointers: false);
                            RecordDataRegion(addr, wordLen, "table", "heuristic: 16-bit word data table");
                            posInCode += wordLen;
                            continue;
                        }
                    }

                    if (TryDetectLowEntropy(posInCode, out var lowEntLen))
                    {
                        lowEntLen = Math.Min(lowEntLen, clampLimit);
                        var span = code.AsSpan(posInCode, Math.Min(lowEntLen, code.Length - posInCode));
                        var rowW = GuessRepeatingRowWidth(span);
                        var rowNote = rowW.HasValue
                            ? $" rowsize={rowW.Value}B width~{rowW.Value * 8}px@1bpp/{rowW.Value * 4}px@2bpp/{rowW.Value * 2}px@4bpp rows~{Math.Max(1, lowEntLen / rowW.Value)}"
                            : string.Empty;
                        sb.AppendLine($"; heuristic: low-entropy block (likely bitmap/tile/pattern data) bytes={lowEntLen}{rowNote}");
                        EmitDbBytes(addr, lowEntLen);
                        RecordDataRegion(addr, lowEntLen, "data", "heuristic: low-entropy block (bitmap/tile/pattern candidate)");
                        posInCode += lowEntLen;
                        continue;
                    }

                    }
                }

                // If the next carve start is inside the next decoded instruction, resync by emitting db bytes up to the carve.
                if (emitInlineStringLabels && nextCarveStart != uint.MaxValue && nextCarveStart > addr)
                {
                    if (insByAddr.TryGetValue(addr, out var maybeIns))
                    {
                        var nextAddr = addr + (uint)(maybeIns.Bytes?.Length ?? 0);
                        if (nextAddr > nextCarveStart)
                        {
                            var dbCount = (int)(nextCarveStart - addr);
                            if (dbCount > 0)
                            {
                                EmitDbBytes(addr, dbCount);
                                posInCode += dbCount;
                                continue;
                            }
                        }
                    }
                }

                if (!insByAddr.TryGetValue(addr, out var ins))
                {
                    // Should not happen, but if we can't decode at this address, emit a single byte and move on.
                    EmitDbBytes(addr, 1);
                    RecordDataRegion(addr, 1, "data", "decode failed at address (fallback db)");
                    posInCode += 1;
                    continue;
                }

                var bytes = ins.Bytes ?? Array.Empty<byte>();
                var bytesHex = string.Concat(bytes.Select(b => b.ToString("X2")));
                var insText = ins.ToString();
                var comment = string.Empty;
                var forceDbInInstrMode = false;

                var isInvalid = insText.StartsWith("invalid", StringComparison.OrdinalIgnoreCase);
                if (masmCompat && masmCompatEmitInstructions && isInvalid)
                {
                    // Ensure -BININSTR output remains assemblable by falling back to raw bytes for invalid opcodes.
                    sb.AppendLine($"db {string.Join(", ", bytes.Select(ToMasmHexByte))} ; {addr:X8}h invalid opcode (fallback to db)");
                    posInCode += bytes.Length > 0 ? bytes.Length : 1;
                    continue;
                }

                if (binInsights && (reachableInsAddrs.Count == 0 || !reachableInsAddrs.Contains(addr)) && insText.StartsWith("invalid", StringComparison.OrdinalIgnoreCase))
                {
                    if (masmCompat)
                    {
                        sb.AppendLine($"db {string.Join(", ", bytes.Select(ToMasmHexByte))} ; {addr:X8}h {insText} | heuristic: invalid opcode (likely data)");
                        RecordDataRegion(addr, bytes.Length > 0 ? bytes.Length : 1, "data", "heuristic: invalid opcode (likely data)");
                        posInCode += bytes.Length > 0 ? bytes.Length : 1;
                        continue;
                    }
                    else
                    {
                        sb.AppendLine($"{addr:X8}h {bytesHex,-16} db {string.Join(", ", bytes.Select(b => $"0x{b:X2}"))} ; heuristic: invalid opcode (likely data)");
                        RecordDataRegion(addr, bytes.Length > 0 ? bytes.Length : 1, "data", "heuristic: invalid opcode (likely data)");
                        posInCode += bytes.Length > 0 ? bytes.Length : 1;
                        continue;
                    }
                }

                // Rewrite rel-target operands to labels.
                if (TryGetRelativeBranchTarget16(ins, out var brTarget, out var isCall))
                {
                    if (binInsights)
                    {
                        if (labelByAddr.Count > 0 && labelByAddr.TryGetValue(brTarget, out var lbl))
                        {
                            if (isCall && functionStarts.Contains(brTarget))
                                lbl = $"func_{brTarget:X5}";

                            insText = RewriteFirstAddressToken(insText, lbl);
                        }
                    }
                    else if (emitAsmLabels && RequiresLabelForWatcomRelTarget16(ins))
                    {
                        if (labelByAddr.TryGetValue(brTarget, out var lbl))
                        {
                            insText = RewriteFirstAddressToken(insText, lbl);
                        }
                        else
                        {
                            // OpenWatcom doesn't accept numeric targets for CALL/JCXZ/LOOP*.
                            // In instruction-emitting mode we must fall back to db if we cannot label.
                            // In comment-only mnemonic mode we can keep the numeric operand.
                            if (masmCompatEmitInstructions)
                                forceDbInInstrMode = true;
                        }
                    }
                }

                if (hexRe != null)
                {
                    // Avoid annotating control-flow instructions (branch targets often alias string addresses).
                    // Use insText (stable) instead of ins.Mnemonic enum formatting (library-specific).
                    var mnemonicTok = insText.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault() ?? string.Empty;

                    var afterMnemonic = insText.Length > mnemonicTok.Length
                        ? insText.Substring(mnemonicTok.Length).TrimStart()
                        : string.Empty;

                    // Also restrict to mnemonics that commonly carry pointers/immediates to data.
                    var isPointery = mnemonicTok.Equals("mov", StringComparison.OrdinalIgnoreCase) ||
                                    mnemonicTok.Equals("lea", StringComparison.OrdinalIgnoreCase) ||
                                    mnemonicTok.Equals("push", StringComparison.OrdinalIgnoreCase);

                    // Further restrict: for mov, prefer register-immediate / register-address forms (skip stores like: mov [0x1234], ax)
                    if (mnemonicTok.Equals("mov", StringComparison.OrdinalIgnoreCase) && afterMnemonic.StartsWith("[", StringComparison.Ordinal))
                        isPointery = false;

                    if (isPointery && !(mnemonicTok.StartsWith("j", StringComparison.OrdinalIgnoreCase) ||
                                       mnemonicTok.Equals("call", StringComparison.OrdinalIgnoreCase) ||
                                       mnemonicTok.StartsWith("ret", StringComparison.OrdinalIgnoreCase)))
                    {
                    // Best-effort: if the instruction text contains an absolute address that matches a detected string,
                    // append it as a literal. Works well for patterns like: mov dx, 0x1234 / lea si, [0x1234] / mov ax, [0x1234]
                    foreach (Match m in hexRe.Matches(insText))
                    {
                        if (!TryParseAddressToken(m.Value, out var tokVal))
                            continue;

                        if (stringsByAddr.TryGetValue(tokVal, out var sInfo))
                        {
                            // Rewrite the operand itself to a label (LE-style), then keep the literal as a comment.
                            var strLbl = $"str_{tokVal:X4}";
                            insText = insText.Substring(0, m.Index) + strLbl + insText.Substring(m.Index + m.Length);
                            comment = $" ; \"{sInfo.Preview}\"";
                            break;
                        }
                    }
                    }
                }

                if (masmCompat)
                {
                    var asmIns = NormalizeHexLiteralsToMasm(insText);

                    if (masmCompatEmitInstructions || masmCompatEmitInstructionComments)
                        asmIns = FixupWasmInstructionSyntax(asmIns);

                    if (masmCompatEmitInstructions)
                    {
                        // Best-effort instruction output for readability.
                        // If the formatter produces something OpenWatcom WASM doesn't accept, fall back to db
                        // while keeping the decoded mnemonic as a comment.
                        if (forceDbInInstrMode || ShouldFallbackToDbInInstrMode(asmIns))
                        {
                            var dbList = string.Join(",", bytes.Select(ToMasmHexByte));
                            sb.AppendLine($"    db {dbList} ; {addr:X8}h {asmIns}{comment}");
                        }
                        else
                        {
                            // Keep address + bytes in a comment for cross-referencing.
                            sb.AppendLine($"    {asmIns} ; {addr:X8}h {bytesHex}{comment}");
                        }
                    }
                    else
                    {
                        // Always byte-perfect: emit the exact bytes as db.
                        // If masmCompatEmitInstructionComments is enabled, keep the decoded mnemonic as a comment
                        // so the output remains readable while reassembling to the identical binary.
                        var dbList = string.Join(",", bytes.Select(ToMasmHexByte));
                        sb.AppendLine($"    db {dbList} ; {addr:X8}h {asmIns}{comment}");
                    }
                }
                else
                {
                    sb.AppendLine($"{addr:X8}h {bytesHex,-16} {insText}{comment}");
                }

                posInCode += bytes.Length > 0 ? bytes.Length : 1;
            }

            if (masmCompat && masmCompatEmitCodeMap)
            {
                sb.AppendLine();
                sb.AppendLine(";-------------------------------------------");
                sb.AppendLine("; CODE MAP (best-effort)");
                sb.AppendLine("; The binary bytes are authoritative; this map is heuristic and based on reachability + data detectors.");
                sb.AppendLine(";-------------------------------------------");

                sb.AppendLine($"; entrypoint: {origin:X5}h");
                if (extraEntryPoints.Count > 0)
                {
                    var eps = string.Join(", ", extraEntryPoints.OrderBy(x => x).Take(32).Select(x => $"{x:X5}h"));
                    sb.AppendLine($"; extra entrypoints (scan): {eps}{(extraEntryPoints.Count > 32 ? " ..." : string.Empty)}");
                }

                if (indirectJmpCount > 0 || indirectCallCount > 0)
                    sb.AppendLine($"; indirect ctl: ijmp={indirectJmpCount} icall={indirectCallCount} anchored_tables={jumpTableAnchors.Select(x => x.candidateAddr).Distinct().Count()}");

                if (interruptVectors.Count > 0)
                {
                    var ints = string.Join(", ", interruptVectors
                        .OrderByDescending(k => k.Value)
                        .ThenBy(k => k.Key)
                        .Take(12)
                        .Select(k => $"{k.Key:X2}h({k.Value})"));
                    sb.AppendLine($"; interrupts: total={interruptVectors.Values.Sum()} unique={interruptVectors.Count} top={ints}{(interruptVectors.Count > 12 ? " ..." : string.Empty)}");
                }
                if (portIoCount > 0)
                    sb.AppendLine($"; port-io: in/out count={portIoCount}");
                if (portImm8Counts.Count > 0)
                {
                    var ports = string.Join(", ", portImm8Counts
                        .OrderByDescending(k => k.Value)
                        .ThenBy(k => k.Key)
                        .Take(12)
                        .Select(k => $"{k.Key:X2}h({k.Value})"));
                    sb.AppendLine($"; ports(imm8): unique={portImm8Counts.Count} top={ports}{(portImm8Counts.Count > 12 ? " ..." : string.Empty)}");
                }
                if (farCallCount > 0 || farJmpCount > 0)
                    sb.AppendLine($"; far ctl: callf={farCallCount} jmpf={farJmpCount}");

                // Precompute reachable code byte ranges from the reachability walk.
                var reachableCodeRanges = new List<(uint start, uint endExcl)>();
                if (reachableInsAddrs.Count > 0)
                {
                    var addrs = reachableInsAddrs.OrderBy(a => a).ToList();
                    uint? curStart = null;
                    uint curEnd = 0;

                    void FlushCodeRange()
                    {
                        if (!curStart.HasValue)
                            return;
                        reachableCodeRanges.Add((curStart.Value, curEnd));
                        curStart = null;
                        curEnd = 0;
                    }

                    foreach (var a in addrs)
                    {
                        if (!insByAddr.TryGetValue(a, out var ins))
                            continue;
                        var len = (uint)((ins.Bytes?.Length ?? 1) == 0 ? 1 : (ins.Bytes?.Length ?? 1));
                        if (!curStart.HasValue)
                        {
                            curStart = a;
                            curEnd = a + len;
                            continue;
                        }

                        if (a == curEnd)
                        {
                            curEnd = a + len;
                        }
                        else
                        {
                            FlushCodeRange();
                            curStart = a;
                            curEnd = a + len;
                        }
                    }
                    FlushCodeRange();
                }

                static bool IsInRanges(uint addr, List<(uint start, uint endExcl)> ranges)
                {
                    foreach (var r in ranges)
                    {
                        if (addr >= r.start && addr < r.endExcl)
                            return true;
                    }
                    return false;
                }

                if (absMemXrefs.Count > 0)
                {
                    // Convert repeated absolute memory xrefs into small "data" hints, but only when the target is not also reachable code bytes.
                    foreach (var kvp in absMemXrefs)
                    {
                        var tgt = kvp.Key;
                        if (reachableCodeRanges.Count > 0 && IsInRanges(tgt, reachableCodeRanges))
                            continue;
                        RecordDataRegion(tgt, 2, "data", $"xref: abs mem reference (refs={kvp.Value.Distinct().Count()})");
                    }

                    var topX = string.Join(", ", absMemXrefs
                        .OrderByDescending(k => k.Value.Distinct().Count())
                        .ThenBy(k => k.Key)
                        .Take(12)
                        .Select(k => $"{k.Key:X5}h({k.Value.Distinct().Count()})"));
                    sb.AppendLine($"; xref(abs-mem): targets={absMemXrefs.Count} top={topX}{(absMemXrefs.Count > 12 ? " ..." : string.Empty)}");
                }

                if (absMemWrites.Count > 0 && reachableCodeRanges.Count > 0)
                {
                    var writeTargetsInCode = absMemWrites.Keys.Where(t => IsInRanges(t, reachableCodeRanges)).ToList();
                    if (writeTargetsInCode.Count > 0)
                    {
                        var writeSites = writeTargetsInCode
                            .SelectMany(t => absMemWrites.TryGetValue(t, out var srcs) ? srcs : Enumerable.Empty<uint>())
                            .Distinct()
                            .Count();
                        sb.AppendLine($"; selfmod?: abs-mem writes into reachable code targets={writeTargetsInCode.Count} sites={writeSites}");
                    }
                }

                // Best-effort function extents (within reachable code) derived from call targets + prolog detection.
                if (functionStarts.Count > 0)
                {
                    bool IsReturnOpcode(byte op) => op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA || op == 0xCF;

                    bool TryComputeFunctionExtent(uint start, out uint min, out uint maxExcl, out int insCount, out int retCount)
                    {
                        min = start;
                        maxExcl = start;
                        insCount = 0;
                        retCount = 0;

                        if (!insByAddr.TryGetValue(start, out var startIns))
                            return false;
                        if (!reachableInsAddrs.Contains(start))
                            return false;

                        var visited = new HashSet<uint>();
                        var pending = new Stack<uint>();
                        pending.Push(start);

                        while (pending.Count > 0)
                        {
                            var a = pending.Pop();
                            if (!visited.Add(a))
                                continue;
                            if (!reachableInsAddrs.Contains(a))
                                continue;
                            if (!insByAddr.TryGetValue(a, out var ins))
                                continue;

                            var b = ins.Bytes ?? Array.Empty<byte>();
                            var len = (uint)(b.Length == 0 ? 1 : b.Length);
                            insCount++;
                            if (a < min)
                                min = a;
                            if (a + len > maxExcl)
                                maxExcl = a + len;

                            if (b.Length > 0 && IsReturnOpcode(b[0]))
                            {
                                retCount++;
                                continue;
                            }

                            var next = a + len;

                            // Follow relative branches/jumps inside the same function.
                            if (TryGetRelativeBranchTarget16(ins, out var tgt, out var isCall))
                            {
                                // Do not inline callees.
                                if (isCall)
                                {
                                    // Still follow fallthrough.
                                    pending.Push(next);
                                    continue;
                                }

                                // Stop at edges into other known function starts (avoid swallowing multiple funcs).
                                if (tgt != start && functionStarts.Contains(tgt))
                                {
                                    pending.Push(next);
                                    continue;
                                }

                                pending.Push(tgt);
                                pending.Push(next);
                                continue;
                            }

                            // Default fallthrough.
                            pending.Push(next);
                        }

                        return insCount > 0;
                    }

                    var startsInImage = functionStarts
                        .Where(a => a >= origin && a < origin + (uint)code.Length)
                        .Distinct()
                        .OrderBy(a => a)
                        .ToList();

                    var funcLines = new List<string>();
                    foreach (var f in startsInImage)
                    {
                        if (!TryComputeFunctionExtent(f, out var fmin, out var fmaxExcl, out var ic, out var rc))
                            continue;
                        var callers = callXrefs.TryGetValue(f, out var srcs) ? srcs.Distinct().Count() : 0;
                        funcLines.Add($"; func: {f:X5}h..{(fmaxExcl - 1):X5}h (ins={ic} rets={rc} callers={callers})");
                    }

                    if (funcLines.Count > 0)
                    {
                        sb.AppendLine($"; functions: starts={startsInImage.Count} extents={funcLines.Count} (top)");
                        foreach (var ln in funcLines.Take(48))
                            sb.AppendLine(ln);
                        if (funcLines.Count > 48)
                            sb.AppendLine($";   ... ({funcLines.Count - 48} more)");
                    }
                }

                // Code ranges from reachability walk.
                if (reachableInsAddrs.Count == 0)
                {
                    sb.AppendLine("; code: (none detected by reachability walk)");
                }
                else
                {
                    foreach (var r in reachableCodeRanges)
                        sb.AppendLine($"; code: {r.start:X5}h..{(r.endExcl - 1):X5}h (len={(r.endExcl - r.start)})");
                }

                // Callgraph summary (relative CALLs only).
                if (callXrefs.Count > 0)
                {
                    sb.AppendLine("; callgraph: targets with callers (top)");
                    foreach (var kvp in callXrefs.OrderByDescending(k => k.Value.Distinct().Count()).ThenBy(k => k.Key).Take(64))
                    {
                        var tgt = kvp.Key;
                        var callers = kvp.Value.Distinct().OrderBy(x => x).Take(8).Select(x => $"{x:X5}h");
                        sb.AppendLine($";   {tgt:X5}h callers={kvp.Value.Distinct().Count()} from {string.Join(", ", callers)}{(kvp.Value.Distinct().Count() > 8 ? " ..." : string.Empty)}");
                    }
                }

                // Data ranges recorded during rendering (merge overlaps/adjacent).
                if (dataRegions.Count == 0)
                {
                    sb.AppendLine("; data: (no heuristic data regions recorded)");
                }
                else
                {
                    foreach (var grp in dataRegions
                                 .OrderBy(r => r.start)
                                 .ThenBy(r => r.endExcl)
                                 .GroupBy(r => r.kind))
                    {
                        var regions = grp.ToList();
                        regions.Sort((a, b) => a.start.CompareTo(b.start));

                        // Merge per kind.
                        var merged = new List<(uint s, uint e, string reason)>();
                        foreach (var r in regions)
                        {
                            if (merged.Count == 0)
                            {
                                merged.Add((r.start, r.endExcl, r.reason));
                                continue;
                            }

                            var last = merged[merged.Count - 1];
                            if (r.start <= last.e)
                            {
                                var newEnd = Math.Max(last.e, r.endExcl);
                                var newReason = last.reason == r.reason || string.IsNullOrWhiteSpace(r.reason) ? last.reason : last.reason;
                                merged[merged.Count - 1] = (last.s, newEnd, newReason);
                            }
                            else if (r.start == last.e)
                            {
                                merged[merged.Count - 1] = (last.s, r.endExcl, last.reason);
                            }
                            else
                            {
                                merged.Add((r.start, r.endExcl, r.reason));
                            }
                        }

                        sb.AppendLine($"; data kind: {grp.Key} ({merged.Count} region(s))");
                        foreach (var m in merged.Take(256))
                        {
                            var len = m.e - m.s;
                            var why = string.IsNullOrWhiteSpace(m.reason) ? string.Empty : $" ; {m.reason}";
                            sb.AppendLine($";   {m.s:X5}h..{(m.e - 1):X5}h (len={len}){why}");
                        }
                        if (merged.Count > 256)
                            sb.AppendLine($";   ... ({merged.Count - 256} more)");
                    }
                }
            }

            if (masmCompat)
            {
                sb.AppendLine();
                sb.AppendLine("end start");
            }

            output = sb.ToString();
            return true;
        }

        public static bool TryDisassembleToString(
            string inputFile,
            uint origin,
            int? bytesLimit,
            bool masmCompat,
            bool binInsights,
            bool emitInlineStringLabels,
            out string output,
            out string error)
        {
            return TryDisassembleToString(
                inputFile,
                origin,
                bytesLimit,
                masmCompat,
                binInsights,
                emitInlineStringLabels,
                masmCompatEmitInstructions: false,
                masmCompatEmitInstructionComments: false,
                masmCompatEmitCodeMap: false,
                out output,
                out error);
        }

        public static bool TryDisassembleToString(
            string inputFile,
            uint origin,
            int? bytesLimit,
            bool masmCompat,
            bool binInsights,
            bool emitInlineStringLabels,
            bool masmCompatEmitInstructions,
            out string output,
            out string error)
        {
            return TryDisassembleToString(
                inputFile,
                origin,
                bytesLimit,
                masmCompat,
                binInsights,
                emitInlineStringLabels,
                masmCompatEmitInstructions,
                masmCompatEmitInstructionComments: false,
                masmCompatEmitCodeMap: false,
                out output,
                out error);
        }

        public static bool TryDisassembleToString(
            string inputFile,
            uint origin,
            int? bytesLimit,
            bool masmCompat,
            bool binInsights,
            bool emitInlineStringLabels,
            bool masmCompatEmitInstructions,
            bool masmCompatEmitInstructionComments,
            out string output,
            out string error)
        {
            return TryDisassembleToString(
                inputFile,
                origin,
                bytesLimit,
                masmCompat,
                binInsights,
                emitInlineStringLabels,
                masmCompatEmitInstructions,
                masmCompatEmitInstructionComments,
                masmCompatEmitCodeMap: false,
                out output,
                out error);
        }

        private static bool TryGetRelativeBranchTarget16(Instruction ins, out uint target, out bool isCall)
        {
            target = 0;
            isCall = false;

            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return false;

            var op0 = b[0];
            var next = (uint)ins.Offset + (uint)b.Length;

            // CALL rel16
            if (op0 == 0xE8 && b.Length >= 3)
            {
                var rel = (short)(b[1] | (b[2] << 8));
                target = (uint)(next + (uint)rel);
                isCall = true;
                return true;
            }

            // JMP rel16
            if (op0 == 0xE9 && b.Length >= 3)
            {
                var rel = (short)(b[1] | (b[2] << 8));
                target = (uint)(next + (uint)rel);
                return true;
            }

            // JMP rel8
            if (op0 == 0xEB && b.Length >= 2)
            {
                var rel = unchecked((sbyte)b[1]);
                target = (uint)(next + (uint)rel);
                return true;
            }

            // Jcc short
            if (op0 >= 0x70 && op0 <= 0x7F && b.Length >= 2)
            {
                var rel = unchecked((sbyte)b[1]);
                target = (uint)(next + (uint)rel);
                return true;
            }

            // JCXZ / LOOP / LOOPE / LOOPNE (short)
            if ((op0 == 0xE3 || op0 == 0xE0 || op0 == 0xE1 || op0 == 0xE2) && b.Length >= 2)
            {
                var rel = unchecked((sbyte)b[1]);
                target = (uint)(next + (uint)rel);
                return true;
            }

            // Jcc near: 0F 8x rel16
            if (op0 == 0x0F && b.Length >= 4)
            {
                var op1 = b[1];
                if (op1 >= 0x80 && op1 <= 0x8F)
                {
                    var rel = (short)(b[2] | (b[3] << 8));
                    target = (uint)(next + (uint)rel);
                    return true;
                }
            }

            return false;
        }

        private static bool RequiresLabelForWatcomRelTarget16(Instruction ins)
        {
            var b = ins.Bytes;
            if (b == null || b.Length == 0)
                return false;

            var op0 = b[0];

            // Relative CALL needs a label in WASM (numeric targets are rejected).
            if (op0 == 0xE8)
                return true;

            // Relative JMP (short/near) also needs a label.
            if (op0 == 0xEB || op0 == 0xE9)
                return true;

            // JCXZ / LOOP / LOOPE / LOOPNE need labels too.
            if (op0 == 0xE3 || op0 == 0xE0 || op0 == 0xE1 || op0 == 0xE2)
                return true;

            return false;
        }

        private static string FixupWasmInstructionSyntax(string asmIns)
        {
            if (string.IsNullOrWhiteSpace(asmIns))
                return asmIns;

            var trimmed = asmIns.Trim();
            if (trimmed.Equals("pushfw", StringComparison.OrdinalIgnoreCase))
                return "pushf";
            if (trimmed.Equals("popfw", StringComparison.OrdinalIgnoreCase))
                return "popf";
            if (trimmed.Equals("iretw", StringComparison.OrdinalIgnoreCase))
                return "iret";
            if (trimmed.Equals("int1", StringComparison.OrdinalIgnoreCase))
                return "int 1";
            if (trimmed.Equals("int3", StringComparison.OrdinalIgnoreCase))
                return "int 3";

            // SharpDisasm often emits segment overrides as: [es:70h]
            // OpenWatcom WASM expects: es:[70h]
            asmIns = Regex.Replace(
                asmIns,
                @"\[(cs|ds|es|ss):",
                m => m.Groups[1].Value + ":[",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            // Split into mnemonic + operands.
            var firstSpace = asmIns.IndexOf(' ');
            if (firstSpace <= 0)
                return asmIns;

            var mnemonic = asmIns.Substring(0, firstSpace).Trim();
            var operandsText = asmIns.Substring(firstSpace + 1);

            var operands = SplitOperandsRespectingBrackets(operandsText);
            if (operands.Count == 0)
                return asmIns;

            // Determine the best-effort memory operand size from the other operand(s).
            var joinedOtherOps = string.Join(" ", operands.Where(o => !o.Contains('[', StringComparison.Ordinal)));
            var inferredSize = InferMemPtrSize(joinedOtherOps);

            for (var i = 0; i < operands.Count; i++)
            {
                var op = operands[i].Trim();
                if (!op.Contains('[', StringComparison.Ordinal))
                    continue;

                // Keep explicit sizing if already present.
                if (op.IndexOf("ptr", StringComparison.OrdinalIgnoreCase) >= 0)
                    continue;

                // If the operand is already prefixed with "word" or "byte" (without ptr), WASM often needs "ptr".
                if (op.StartsWith("word ", StringComparison.OrdinalIgnoreCase) && op.IndexOf("ptr", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    operands[i] = "word ptr " + op.Substring("word ".Length);
                    operands[i] = EnsureSegmentForAbsoluteDisp(operands[i]);
                    continue;
                }
                if (op.StartsWith("byte ", StringComparison.OrdinalIgnoreCase) && op.IndexOf("ptr", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    operands[i] = "byte ptr " + op.Substring("byte ".Length);
                    operands[i] = EnsureSegmentForAbsoluteDisp(operands[i]);
                    continue;
                }

                // Default: prefix size for the memory operand.
                operands[i] = (inferredSize == EnumMemPtrSize.Byte ? "byte ptr " : "word ptr ") + op;

                // OpenWatcom WASM is strict about absolute [disp] memory references when used with PTR.
                // Ensure an explicit segment prefix (ds:) so forms like `add word ptr [6h], ax` become valid.
                operands[i] = EnsureSegmentForAbsoluteDisp(operands[i]);
            }

            return mnemonic + " " + string.Join(", ", operands.Select(o => o.Trim()));
        }

        private static bool ShouldFallbackToDbInInstrMode(string asmIns)
        {
            if (string.IsNullOrWhiteSpace(asmIns))
                return true;

            var s = asmIns.Trim().ToLowerInvariant();

            // Invalid decode.
            if (s.StartsWith("invalid", StringComparison.Ordinal))
                return true;

            // Prefix handling: in BIN16 mnemonic mode we prefer db over trying to normalize
            // prefix syntax (SharpDisasm may emit prefix-like pseudo mnemonics or place LOCK
            // before size tokens, which OpenWatcom rejects).
            if (s == "lock" || s.StartsWith("lock ", StringComparison.Ordinal))
                return true;

            if (s == "rep" || s.StartsWith("rep ", StringComparison.Ordinal))
                return true;
            if (s == "repe" || s.StartsWith("repe ", StringComparison.Ordinal))
                return true;
            if (s == "repne" || s.StartsWith("repne ", StringComparison.Ordinal))
                return true;
            if (s == "repz" || s.StartsWith("repz ", StringComparison.Ordinal))
                return true;
            if (s == "repnz" || s.StartsWith("repnz ", StringComparison.Ordinal))
                return true;

            // SharpDisasm emits prefixes as pseudo-mnemonics (o32/a32) and can place LOCK oddly.
            if (s.StartsWith("o32 ", StringComparison.Ordinal) || s.StartsWith("a32 ", StringComparison.Ordinal))
                return true;
            if (s.Contains(" o32 ", StringComparison.Ordinal) || s.Contains(" a32 ", StringComparison.Ordinal))
                return true;

            // SharpDisasm sometimes renders odd far memory forms like "far word [..]".
            // That representation is not stable/assemblable in OpenWatcom; use db instead.
            if (s.Contains(" far word ", StringComparison.Ordinal))
                return true;

            // Far pointers with an immediate segment (e.g. 0BEBEh:0AA0h) are rejected by WASM.
            if (Regex.IsMatch(s, @"\b[0-9a-f]+h:\b", RegexOptions.CultureInvariant))
                return true;

            // Avoid fs/gs segment prefixes in assembler output (often indicates mis-decoded data for 16-bit DOS blobs).
            if (s.Contains("fs:", StringComparison.Ordinal) || s.Contains("gs:", StringComparison.Ordinal))
                return true;

            // Obvious 32-bit/system instructions are very likely decoded data in a 16-bit DOS blob.
            if (s.StartsWith("sysret", StringComparison.Ordinal) || s.StartsWith("syscall", StringComparison.Ordinal) || s.StartsWith("sysexit", StringComparison.Ordinal))
                return true;
            if (s.StartsWith("cmov", StringComparison.Ordinal))
                return true;

            // 32-bit register names are a strong signal of decoded data (and often lead to CPU/operand errors).
            if (Regex.IsMatch(s, @"\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b", RegexOptions.CultureInvariant))
                return true;

            // x87/MMX/SSE register tokens are also a strong signal of decoded data.
            if (Regex.IsMatch(s, @"\b(st\d|mm\d|xmm\d)\b", RegexOptions.CultureInvariant))
                return true;

            // x87-ish mnemonics can be emitted even without explicit st-register tokens.
            // In BIN16 exports these are overwhelmingly decoded data and frequently rejected by WASM.
            var mnemonicTok = s.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
            if (mnemonicTok.Length > 0 && mnemonicTok[0] == 'f' && !mnemonicTok.Equals("far", StringComparison.Ordinal))
                return true;

            // Large immediates (8+ hex digits) don't belong in BIN16 output; WASM will also reject many.
            if (Regex.IsMatch(s, @"\b[0-9a-f]{8,}h\b", RegexOptions.CultureInvariant))
                return true;

            // Multi-byte NOPs rendered as `nop word ptr [...]` are not accepted by WASM.
            if (s.StartsWith("nop ", StringComparison.Ordinal))
                return true;

            // If we see an obvious decode artifact, prefer db.
            if (s.Contains("??", StringComparison.Ordinal))
                return true;

            return false;
        }

        private static string EnsureSegmentForAbsoluteDisp(string operand)
        {
            if (string.IsNullOrWhiteSpace(operand))
                return operand;

            // If there's already an explicit segment override, keep it.
            if (Regex.IsMatch(operand, @"\b(cs|ds|es|ss):\s*\[", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return operand;

            var open = operand.IndexOf('[');
            if (open < 0)
                return operand;
            var close = operand.IndexOf(']', open + 1);
            if (close < 0)
                return operand;

            var inner = operand.Substring(open + 1, close - open - 1).Trim();

            // Only apply to absolute displacements like [6h], [0AECh], [1234h].
            // Avoid touching register-based addressing ([bp+si+...]) where adding a segment override could change bytes.
            if (!Regex.IsMatch(inner, @"^[0-9A-Fa-f]+h?$", RegexOptions.CultureInvariant))
                return operand;

            return operand.Substring(0, open) + "ds:" + operand.Substring(open);
        }

        private enum EnumMemPtrSize
        {
            Byte,
            Word,
        }

        private static EnumMemPtrSize InferMemPtrSize(string otherOperands)
        {
            if (string.IsNullOrWhiteSpace(otherOperands))
                return EnumMemPtrSize.Word;

            var s = otherOperands.ToLowerInvariant();

            // 8-bit regs
            if (Regex.IsMatch(s, @"\b(al|ah|bl|bh|cl|ch|dl|dh)\b", RegexOptions.CultureInvariant))
                return EnumMemPtrSize.Byte;

            // Segment regs imply 16-bit moves
            if (Regex.IsMatch(s, @"\b(cs|ds|es|ss)\b", RegexOptions.CultureInvariant))
                return EnumMemPtrSize.Word;

            // 16-bit regs
            if (Regex.IsMatch(s, @"\b(ax|bx|cx|dx|si|di|bp|sp)\b", RegexOptions.CultureInvariant))
                return EnumMemPtrSize.Word;

            return EnumMemPtrSize.Word;
        }

        private static List<string> SplitOperandsRespectingBrackets(string operandsText)
        {
            var result = new List<string>();
            if (string.IsNullOrWhiteSpace(operandsText))
                return result;

            var sb = new StringBuilder();
            var bracketDepth = 0;
            foreach (var ch in operandsText)
            {
                if (ch == '[')
                    bracketDepth++;
                else if (ch == ']')
                    bracketDepth = Math.Max(0, bracketDepth - 1);

                if (ch == ',' && bracketDepth == 0)
                {
                    result.Add(sb.ToString());
                    sb.Clear();
                    continue;
                }

                sb.Append(ch);
            }

            if (sb.Length > 0)
                result.Add(sb.ToString());

            return result;
        }

        private static string RewriteFirstAddressToken(string insText, string replacement)
        {
            if (string.IsNullOrWhiteSpace(insText) || string.IsNullOrWhiteSpace(replacement))
                return insText;

            // Prefer 0xNNNN style
            var m = Regex.Match(insText, @"0x[0-9a-fA-F]+", RegexOptions.CultureInvariant);
            if (m.Success)
                return insText.Substring(0, m.Index) + replacement + insText.Substring(m.Index + m.Length);

            // Fallback: NNNNh style
            m = Regex.Match(insText, @"\b[0-9a-fA-F]{3,6}h\b", RegexOptions.CultureInvariant);
            if (m.Success)
                return insText.Substring(0, m.Index) + replacement + insText.Substring(m.Index + m.Length);

            return insText;
        }

        private static Dictionary<uint, BinString> ScanStrings(byte[] bytes, uint origin, int minLen, int maxCount, bool allowTokens = false)
        {
            var map = new Dictionary<uint, BinString>();
            if (bytes == null || bytes.Length == 0)
                return map;

            bool IsPrintable(byte b) => b >= 0x20 && b <= 0x7E;

            bool LooksLikeStart(int idx)
            {
                if (idx < 0 || idx >= bytes.Length)
                    return false;

                if (IsPrintable(bytes[idx]))
                    return true;

                if (!allowTokens)
                    return false;

                // Common: a control prefix (03 xx) followed by printable text.
                if (bytes[idx] == 0x03 && idx + 2 < bytes.Length && IsPrintable(bytes[idx + 2]))
                    return true;

                // Many DOS games embed low control bytes as formatting tokens (color/position/etc),
                // often 1-2 bytes immediately before a printable run.
                if (bytes[idx] != 0x00 && bytes[idx] < 0x20)
                {
                    for (var look = 1; look <= 3 && idx + look < bytes.Length; look++)
                    {
                        if (IsPrintable(bytes[idx + look]))
                            return true;
                    }
                }

                return false;
            }

            for (var i = 0; i < bytes.Length && map.Count < maxCount; i++)
            {
                if (!LooksLikeStart(i))
                    continue;

                var start = i;

                var printableCount = 0;
                var tokenCount = 0;
                var preview = new StringBuilder(160);

                while (i < bytes.Length)
                {
                    var b = bytes[i];

                    // NUL terminator ends the string.
                    if (b == 0x00)
                        break;

                    if (IsPrintable(b))
                    {
                        printableCount++;
                        if (preview.Length < 120)
                            preview.Append((char)b);
                        i++;
                        continue;
                    }

                    if (!allowTokens)
                        break;

                    // Treat CR/LF as printable escapes.
                    if (b == 0x0D)
                    {
                        printableCount++;
                        if (preview.Length < 118)
                            preview.Append("\\r");
                        i++;
                        continue;
                    }
                    if (b == 0x0A)
                    {
                        printableCount++;
                        if (preview.Length < 118)
                            preview.Append("\\n");
                        i++;
                        continue;
                    }

                    // In-band control sequence: 03 xx
                    if (b == 0x03 && i + 1 < bytes.Length)
                    {
                        tokenCount += 2;
                        var arg = bytes[i + 1];
                        if (preview.Length < 110)
                        {
                            if (arg == 0x0A)
                                preview.Append("\\n");
                            else if (arg == 0x0D)
                                preview.Append("\\r");
                            else
                                preview.Append($"<03{arg:X2}>");
                        }
                        i += 2;
                        continue;
                    }

                    // Other low control bytes are frequently formatting tokens (e.g., 07 14, 18 14, 0B 0F, ...).
                    // Treat them as tokens instead of terminating the string, as long as allowTokens is enabled.
                    if (b != 0x00 && b < 0x20)
                    {
                        tokenCount++;
                        if (preview.Length < 116)
                            preview.Append($"<{b:X2}>");
                        i++;
                        continue;
                    }

                    // High-bit tokens (special glyphs / key icons).
                    if (b >= 0x80)
                    {
                        tokenCount++;
                        if (preview.Length < 116)
                            preview.Append($"<{b:X2}>");
                        i++;
                        continue;
                    }

                    // Other control bytes terminate the string scan.
                    break;
                }

                var len = i - start;
                if (len < minLen)
                    continue;

                // Reduce false positives: require a decent amount of ASCII and cap token noise.
                if (allowTokens)
                {
                    if (printableCount < Math.Min(8, minLen))
                        continue;
                    // Must be at least ~40% readable (len counts raw bytes, control sequences consume bytes too).
                    if (printableCount < (int)(len * 0.40))
                        continue;
                    // Don't let token noise dominate.
                    if (tokenCount > (printableCount * 3))
                        continue;
                }

                // Avoid absurdly long runs (often graphics tables that happen to be printable-ish)
                var take = Math.Min(len, 120);

                string s;
                if (!allowTokens)
                {
                    s = Encoding.ASCII.GetString(bytes, start, take);

                    // Sanitize for one-line comments
                    s = s.Replace("\r", "\\r").Replace("\n", "\\n");
                    s = s.Replace("\\", "\\\\").Replace("\"", "\\\"");
                }
                else
                {
                    s = preview.ToString();
                }

                var addr = origin + (uint)start;
                if (!map.ContainsKey(addr))
                    map[addr] = new BinString(addr, len, s);
            }

            return map;
        }

        private static bool TryParseAddressToken(string token, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(token))
                return false;

            var t = token.Trim();
            if (t.EndsWith("h", StringComparison.OrdinalIgnoreCase))
            {
                t = t.Substring(0, t.Length - 1);
                return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out value);
            }

            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                t = t.Substring(2);
                return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out value);
            }

            // Conservative: only accept hex-ish tokens (already filtered by regex)
            return uint.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out value);
        }
    }

}
