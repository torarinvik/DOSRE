using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using SharpDisasm;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Flat 16-bit binary disassembler (COM-like / raw code blobs).
    /// This intentionally does not attempt to infer segments, relocations, or entrypoints.
    /// </summary>
    public static class Bin16Disassembler
    {
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
                stringsByAddr = ScanStrings(fileBytes, origin, minLen: 6, maxCount: 2048);

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

            if (binInsights)
            {
                foreach (var ins in instructions)
                {
                    if (TryGetRelativeBranchTarget16(ins, out var target, out var isCall))
                    {
                        if (target >= origin && target < origin + (uint)code.Length)
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
                    }
                }

                // Heuristic: common function prologue in 16-bit code
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

            // Best-effort reachability: walk relative branches/calls starting at origin.
            // This helps avoid applying data heuristics inside code.
            if (binInsights)
            {
                bool IsReturnOpcode(byte op) => op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA || op == 0xCF;

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

                var pending = new Stack<uint>();
                pending.Push(origin);
                while (pending.Count > 0)
                {
                    var a = pending.Pop();
                    if (!reachableInsAddrs.Add(a))
                        continue;

                    if (!insByAddr.TryGetValue(a, out var ins))
                        continue;

                    var b = ins.Bytes ?? Array.Empty<byte>();
                    if (b.Length == 0)
                        continue;

                    var op0 = b[0];
                    var next = a + (uint)b.Length;

                    if (IsReturnOpcode(op0))
                        continue;

                    if (TryGetRelBranchInfo16(ins, out var target, out var isCall, out var isUncondJmp))
                    {
                        if (target >= origin && target < origin + (uint)code.Length)
                            pending.Push(target);

                        if (isCall)
                            pending.Push(next);
                        else if (!isUncondJmp)
                            pending.Push(next);

                        continue;
                    }

                    if (next >= origin && next < origin + (uint)code.Length)
                        pending.Push(next);
                }
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

            var sb = new StringBuilder();
            sb.AppendLine($"; Disassembly of {Path.GetFileName(inputFile)} (flat 16-bit binary)");
            sb.AppendLine($"; Origin: {(masmCompat ? ToMasmHexU32(origin, 4) : $"0x{origin:X}")}");
            sb.AppendLine($"; Bytes: {(masmCompat ? ToMasmHexU32NoPad((uint)maxBytes) : $"0x{maxBytes:X}")} ({maxBytes})");
            sb.AppendLine(";");

            if (masmCompat)
            {
                sb.AppendLine(".8086");
                sb.AppendLine(".model tiny");
                sb.AppendLine(".code");
                sb.AppendLine($"org {ToMasmHexU32(origin, 4)}");
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
                        var preview = kvp.Value.Preview.Replace('"', '\'');
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

                // Reject ASCII-heavy regions.
                var printable = 0;
                for (var i = 0; i < windowLen; i++)
                {
                    var bb = code[startPos + i];
                    if (bb >= 0x20 && bb <= 0x7E)
                        printable++;
                }
                if (printable >= (int)(windowLen * 0.50))
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

                // Data heuristics (only when insights enabled, and only if this address isn't a known control-flow target).
                if (binInsights && !functionStarts.Contains(addr) && !labelTargets.Contains(addr) && (reachableInsAddrs.Count == 0 || !reachableInsAddrs.Contains(addr)))
                {
                    var clampLimit = nextCarveStart != uint.MaxValue && nextCarveStart > addr
                        ? (int)Math.Min(int.MaxValue, nextCarveStart - addr)
                        : int.MaxValue;

                    if (TryGetFillRun(posInCode, out var fillVal, out var fillLen))
                    {
                        fillLen = Math.Min(fillLen, clampLimit);
                        sb.AppendLine($"; heuristic: padding/fill {(masmCompat ? ToMasmHexByte(fillVal) : $"0x{fillVal:X2}")} x{fillLen}");
                        EmitDbBytes(addr, fillLen);
                        posInCode += fillLen;
                        continue;
                    }

                    if (TryDetectWordPointerTable(posInCode, out var tableLen))
                    {
                        tableLen = Math.Min(tableLen, clampLimit);
                        if (tableLen >= 32)
                        {
                            EmitWordTable(addr, tableLen, "tblp", "16-bit pointer table", rewritePointers: true);
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
                                    ? $"16-bit word table (bit-pattern heavy; likely sprite/bitmap/tile data) rowsize={rowW.Value}B"
                                    : "16-bit word table (bit-pattern heavy; likely sprite/bitmap/tile data)";
                            }
                            else
                            {
                                cmt = "16-bit word table";
                            }
                            EmitWordTable(addr, wordLen, "tblw", cmt, rewritePointers: false);
                            posInCode += wordLen;
                            continue;
                        }
                    }

                    if (TryDetectLowEntropy(posInCode, out var lowEntLen))
                    {
                        lowEntLen = Math.Min(lowEntLen, clampLimit);
                        var span = code.AsSpan(posInCode, Math.Min(lowEntLen, code.Length - posInCode));
                        var rowW = GuessRepeatingRowWidth(span);
                        var rowNote = rowW.HasValue ? $" rowsize={rowW.Value}B" : string.Empty;
                        sb.AppendLine($"; heuristic: low-entropy block (likely bitmap/tile/pattern data) bytes={lowEntLen}{rowNote}");
                        EmitDbBytes(addr, lowEntLen);
                        posInCode += lowEntLen;
                        continue;
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
                    posInCode += 1;
                    continue;
                }

                var bytes = ins.Bytes ?? Array.Empty<byte>();
                var bytesHex = string.Concat(bytes.Select(b => b.ToString("X2")));
                var insText = ins.ToString();
                var comment = string.Empty;

                if (binInsights && (reachableInsAddrs.Count == 0 || !reachableInsAddrs.Contains(addr)) && insText.StartsWith("invalid", StringComparison.OrdinalIgnoreCase))
                {
                    if (masmCompat)
                    {
                        sb.AppendLine($"db {string.Join(", ", bytes.Select(ToMasmHexByte))} ; {addr:X8}h {insText} | heuristic: invalid opcode (likely data)");
                        posInCode += bytes.Length > 0 ? bytes.Length : 1;
                        continue;
                    }
                    else
                    {
                        sb.AppendLine($"{addr:X8}h {bytesHex,-16} db {string.Join(", ", bytes.Select(b => $"0x{b:X2}"))} ; heuristic: invalid opcode (likely data)");
                        posInCode += bytes.Length > 0 ? bytes.Length : 1;
                        continue;
                    }
                }

                // Rewrite branch/call operands to use labels (more readable / navigable output).
                if (binInsights && labelByAddr.Count > 0 && TryGetRelativeBranchTarget16(ins, out var brTarget, out var isCall))
                {
                    if (labelByAddr.TryGetValue(brTarget, out var lbl))
                    {
                        if (isCall && functionStarts.Contains(brTarget))
                            lbl = $"func_{brTarget:X5}";

                        insText = RewriteFirstAddressToken(insText, lbl);
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

                    // OpenWatcom WASM is picky about operand syntax and memory operand sizing.
                    // The safest always-assemblable representation is to emit the exact bytes as db,
                    // and keep the disassembly as a comment for readability (known-good DECA.ASM style).
                    var dbList = string.Join(",", bytes.Select(ToMasmHexByte));
                    sb.AppendLine($"    db {dbList} ; {addr:X8}h {asmIns}{comment}");
                }
                else
                {
                    sb.AppendLine($"{addr:X8}h {bytesHex,-16} {insText}{comment}");
                }

                posInCode += bytes.Length > 0 ? bytes.Length : 1;
            }

            if (masmCompat)
            {
                sb.AppendLine();
                sb.AppendLine("end start");
            }

            output = sb.ToString();
            return true;
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

        private static Dictionary<uint, BinString> ScanStrings(byte[] bytes, uint origin, int minLen, int maxCount)
        {
            var map = new Dictionary<uint, BinString>();
            if (bytes == null || bytes.Length == 0)
                return map;

            bool IsPrintable(byte b) => b >= 0x20 && b <= 0x7E;

            for (var i = 0; i < bytes.Length && map.Count < maxCount; i++)
            {
                if (!IsPrintable(bytes[i]))
                    continue;

                var start = i;
                while (i < bytes.Length && IsPrintable(bytes[i]))
                    i++;

                var len = i - start;
                if (len < minLen)
                    continue;

                // Avoid absurdly long runs (often graphics tables that happen to be printable-ish)
                var take = Math.Min(len, 120);
                var s = Encoding.ASCII.GetString(bytes, start, take);

                // Sanitize for one-line comments
                s = s.Replace("\r", "\\r").Replace("\n", "\\n");
                s = s.Replace("\\", "\\\\").Replace("\"", "\\\"");

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
