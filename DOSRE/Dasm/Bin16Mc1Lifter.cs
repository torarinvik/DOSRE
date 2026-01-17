using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    /// <summary>
    /// Lifts MC0 (Machine-C Level 0) into MC1 (deterministic sugar over MC0).
    ///
    /// This is analogous to how promoted asm is lifted into MC0:
    /// - Preserves the byte-authoritative origin stream (addr+bytes) 1:1.
    /// - Rewrites statement text into more readable forms (consts, views), but never changes origins.
    ///
    /// Notes:
    /// - MC1 declarations are ignored for identity purposes and must be purely additive.
    /// - Rewrites are best-effort and intentionally conservative.
    /// </summary>
    public static class Bin16Mc1Lifter
    {
        public sealed class LiftOptions
        {
            public bool AddInterruptConsts { get; set; } = true;
            public bool LiftDsAbsoluteGlobals { get; set; } = true;

            /// <summary>
            /// Max size of a generated DS "globals" view window, in bytes.
            /// This is a heuristic to avoid emitting enormous structs.
            /// </summary>
            public ushort DsViewMaxSpan { get; set; } = 0x0040;

            /// <summary>
            /// Only lift absolute DS addresses in this inclusive range.
            /// Default focuses on the Decathlon-style 0x04xx globals.
            /// </summary>
            public ushort DsAbsMin { get; set; } = 0x0400;
            public ushort DsAbsMax { get; set; } = 0x04FF;
        }

        private static readonly Dictionary<ushort, (string name, ushort value)> KnownIntConsts = new()
        {
            { 0x0003, ("INT_BREAKPOINT", 0x0003) },
            { 0x0010, ("INT_VIDEO", 0x0010) },
            { 0x0013, ("INT_DISK", 0x0013) },
            { 0x0016, ("INT_KEYBOARD", 0x0016) },
            { 0x0021, ("INT_DOS", 0x0021) },
        };

        private static readonly Regex IntLiteralRx = new Regex(
            @"\bINT\s*\(\s*0x(?<n>[0-9A-Fa-f]{2,4})\s*\)",
            RegexOptions.Compiled);

        private static readonly Regex DsAbsRx = new Regex(
            @"\[(?:ds:)?0x(?<addr>[0-9A-Fa-f]{4})\]",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovLoadRx = new Regex(
            @"^\s*mov\s+(?<dst>[a-z]{2})\s*,\s*\[(?:ds:)?0x(?<addr>[0-9A-Fa-f]{4})\]\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovStoreRx = new Regex(
            @"^\s*mov\s+\[(?:ds:)?0x(?<addr>[0-9A-Fa-f]{4})\]\s*,\s*(?<src>[a-z]{2})\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex Mc0LineRx = new Regex(
            @"^(?<indent>\s*)(?<stmt>.*?);\s*//\s*(?<comment>.*)$",
            RegexOptions.Compiled);

        private static readonly Regex OriginRx = new Regex(
            @"@(?<addr>[0-9A-Fa-f]{1,8})\s+(?<hex>[0-9A-Fa-f]{2,})(?:\s*;\s*(?<asm>.*))?$",
            RegexOptions.Compiled);

        private static readonly Dictionary<string, string> RegMap = new(StringComparer.OrdinalIgnoreCase)
        {
            { "ax", "AX" }, { "bx", "BX" }, { "cx", "CX" }, { "dx", "DX" },
            { "si", "SI" }, { "di", "DI" }, { "bp", "BP" }, { "sp", "SP" },
            { "al", "AL" }, { "ah", "AH" }, { "bl", "BL" }, { "bh", "BH" },
            { "cl", "CL" }, { "ch", "CH" }, { "dl", "DL" }, { "dh", "DH" },
        };

        private sealed class DsAccess
        {
            public ushort Addr;
            public int Size;
            public string Reg;
            public bool IsStore;
        }

        private sealed class DsView
        {
            public ushort Base;
            public ushort End;
            public string ViewName;
            public string TypeName;
            public List<(ushort Off, string Name, string Type)> Fields = new();

            public string RenderTypeDecl()
            {
                var sb = new StringBuilder();
                sb.Append($"type {TypeName} = struct {{ ");
                for (var i = 0; i < Fields.Count; i++)
                {
                    if (i > 0) sb.Append(' ');
                    sb.Append(Fields[i].Name);
                    sb.Append(": ");
                    sb.Append(Fields[i].Type);
                    sb.Append("; ");
                }
                sb.Append("};");
                return sb.ToString();
            }

            public string RenderViewDecl() => $"view {ViewName} at (DS, 0x{Base:X4}) : {TypeName};";
        }

        public static void LiftPromotedAsmToFile(string inPromotedAsm, string outMc1, LiftOptions opts = null)
        {
            if (string.IsNullOrWhiteSpace(inPromotedAsm)) throw new ArgumentException("Missing input asm", nameof(inPromotedAsm));
            if (!File.Exists(inPromotedAsm)) throw new FileNotFoundException("Input asm not found", inPromotedAsm);
            if (string.IsNullOrWhiteSpace(outMc1)) throw new ArgumentException("Missing output mc1", nameof(outMc1));

            opts ??= new LiftOptions();

            var mc0 = Bin16Mc0.LiftPromotedAsmToMc0(inPromotedAsm);
            var mc1 = LiftMc0ToMc1Text(mc0, opts);
            File.WriteAllText(outMc1, mc1);
        }

        public static string LiftMc0ToMc1Text(Bin16Mc0.Mc0File mc0, LiftOptions opts = null)
        {
            if (mc0 == null) throw new ArgumentNullException(nameof(mc0));
            opts ??= new LiftOptions();

            // Phase 1: collect potential rewrites (interrupt consts, DS absolute globals).
            var neededIntConsts = new SortedDictionary<string, ushort>(StringComparer.Ordinal);
            var dsAccesses = new List<DsAccess>();

            foreach (var st in mc0.Statements)
            {
                var stmt = (st.Mc0 ?? string.Empty).Trim();
                if (string.IsNullOrWhiteSpace(stmt)) continue;

                if (opts.AddInterruptConsts)
                {
                    foreach (Match m in IntLiteralRx.Matches(stmt))
                    {
                        var hex = m.Groups["n"].Value;
                        if (ushort.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n))
                        {
                            if (KnownIntConsts.TryGetValue(n, out var def))
                                neededIntConsts[def.name] = def.value;
                        }
                    }
                }

                if (opts.LiftDsAbsoluteGlobals)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(asm)) continue;

                    // Only lift simple mov loads/stores for now.
                    var mLoad = MovLoadRx.Match(asm);
                    if (mLoad.Success)
                    {
                        var dst = mLoad.Groups["dst"].Value;
                        var addrHex = mLoad.Groups["addr"].Value;
                        if (!TryParseU16(addrHex, out var addr)) continue;
                        if (addr < opts.DsAbsMin || addr > opts.DsAbsMax) continue;
                        if (!RegMap.TryGetValue(dst, out var reg)) continue;
                        var size = IsWordReg(dst) ? 2 : 1;
                        dsAccesses.Add(new DsAccess { Addr = addr, Size = size, Reg = reg, IsStore = false });
                        continue;
                    }

                    var mStore = MovStoreRx.Match(asm);
                    if (mStore.Success)
                    {
                        var src = mStore.Groups["src"].Value;
                        var addrHex = mStore.Groups["addr"].Value;
                        if (!TryParseU16(addrHex, out var addr)) continue;
                        if (addr < opts.DsAbsMin || addr > opts.DsAbsMax) continue;
                        if (!RegMap.TryGetValue(src, out var reg)) continue;
                        var size = IsWordReg(src) ? 2 : 1;
                        dsAccesses.Add(new DsAccess { Addr = addr, Size = size, Reg = reg, IsStore = true });
                        continue;
                    }
                }
            }

            // Phase 2: build DS view(s) for collected absolute addresses.
            var dsViews = BuildDsViews(dsAccesses, opts);
            var viewByAddr = new Dictionary<ushort, (string view, string field)>(dsAccesses.Count);

            foreach (var v in dsViews)
            {
                foreach (var f in v.Fields)
                {
                    var off = f.Off;
                    var abs = (ushort)(v.Base + off);
                    viewByAddr[abs] = (v.ViewName, f.Name);
                }
            }

            // Phase 3: emit MC1 text.
            var sb = new StringBuilder();
            sb.AppendLine("// mc1 lifted from mc0");
            if (!string.IsNullOrWhiteSpace(mc0.Source)) sb.AppendLine($"// source: {mc0.Source}");
            if (!string.IsNullOrWhiteSpace(mc0.StreamSha256)) sb.AppendLine($"// stream_sha256: {mc0.StreamSha256}");
            sb.AppendLine("// format: <stmt>; // @AAAAAAAA HEXBYTES ; original asm");
            sb.AppendLine();

            if (neededIntConsts.Count > 0 || dsViews.Count > 0)
            {
                sb.AppendLine("// ---- MC1 declarations (auto) ----");
                if (neededIntConsts.Count > 0)
                {
                    sb.AppendLine("// Interrupt vectors:");
                    foreach (var kv in neededIntConsts)
                        sb.AppendLine($"const {kv.Key}: u16 = 0x{kv.Value:X4};");
                    sb.AppendLine();
                }

                if (dsViews.Count > 0)
                {
                    sb.AppendLine("// DS absolute globals (auto-lifted views):");
                    foreach (var v in dsViews)
                    {
                        sb.AppendLine(v.RenderTypeDecl());
                        sb.AppendLine(v.RenderViewDecl());
                        sb.AppendLine();
                    }
                }
                sb.AppendLine("// ---- MC0 origin-tagged statements ----");
                sb.AppendLine();
            }

            foreach (var st in mc0.Statements)
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
                if (string.IsNullOrWhiteSpace(stmt))
                    continue;

                // Base MC0 line as produced by Bin16Mc0.RenderMc0Text for stable formatting.
                var rendered = RenderMc0Line(st);
                var mLine = Mc0LineRx.Match(rendered);
                if (!mLine.Success)
                {
                    sb.AppendLine(rendered);
                    continue;
                }

                var indent = mLine.Groups["indent"].Value;
                var stmtText = mLine.Groups["stmt"].Value.Trim();
                var comment = mLine.Groups["comment"].Value;

                // Rewrite interrupts.
                if (opts.AddInterruptConsts)
                {
                    stmtText = IntLiteralRx.Replace(stmtText, m =>
                    {
                        var hex = m.Groups["n"].Value;
                        if (!ushort.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var n))
                            return m.Value;
                        if (!KnownIntConsts.TryGetValue(n, out var def))
                            return m.Value;
                        return $"INT({def.name})";
                    });
                }

                // Rewrite DS simple movs into view.field when possible.
                if (opts.LiftDsAbsoluteGlobals)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();

                    var mLoad = MovLoadRx.Match(asm);
                    if (mLoad.Success)
                    {
                        var dst = mLoad.Groups["dst"].Value;
                        var addrHex = mLoad.Groups["addr"].Value;
                        if (TryParseU16(addrHex, out var addr) && viewByAddr.TryGetValue(addr, out var vf) && RegMap.TryGetValue(dst, out var reg))
                        {
                            stmtText = $"{reg} = {vf.view}.{vf.field}";
                        }
                    }
                    else
                    {
                        var mStore = MovStoreRx.Match(asm);
                        if (mStore.Success)
                        {
                            var src = mStore.Groups["src"].Value;
                            var addrHex = mStore.Groups["addr"].Value;
                            if (TryParseU16(addrHex, out var addr) && viewByAddr.TryGetValue(addr, out var vf) && RegMap.TryGetValue(src, out var reg))
                            {
                                stmtText = $"{vf.view}.{vf.field} = {reg}";
                            }
                        }
                    }
                }

                sb.Append(indent);
                sb.Append(stmtText);
                sb.Append("; // ");
                sb.AppendLine(comment);
            }

            return sb.ToString();
        }

        private static string RenderMc0Line(Bin16Mc0.Mc0Stmt st)
        {
            var stmt = (st.Mc0 ?? string.Empty).Trim();
            if (stmt.EndsWith(";", StringComparison.Ordinal))
                stmt = stmt.Substring(0, stmt.Length - 1).TrimEnd();

            var sb = new StringBuilder();
            sb.Append("    ");
            sb.Append(stmt);
            sb.Append("; // @");
            sb.Append(st.Addr.ToString("X8"));
            sb.Append(' ');
            sb.Append((st.BytesHex ?? string.Empty).Trim());
            sb.Append(" ; ");
            sb.Append(st.Asm ?? string.Empty);
            return sb.ToString();
        }

        private static List<DsView> BuildDsViews(List<DsAccess> accesses, LiftOptions opts)
        {
            if (accesses == null || accesses.Count == 0) return new List<DsView>();

            // Deduplicate addresses and decide whether each address is word or byte.
            var sizeByAddr = new Dictionary<ushort, int>();
            foreach (var a in accesses)
            {
                if (!sizeByAddr.TryGetValue(a.Addr, out var sz) || a.Size > sz)
                    sizeByAddr[a.Addr] = a.Size;
            }

            var addrs = sizeByAddr.Keys.OrderBy(x => x).ToList();
            var views = new List<DsView>();

            var i = 0;
            while (i < addrs.Count)
            {
                var first = addrs[i];
                var baseAddr = (ushort)(first & 0xFFF0);
                var end = (ushort)(baseAddr + opts.DsViewMaxSpan - 1);

                // Pull in all addresses within the window.
                var chunk = new List<ushort>();
                while (i < addrs.Count && addrs[i] <= end)
                {
                    chunk.Add(addrs[i]);
                    i++;
                }

                var v = new DsView
                {
                    Base = baseAddr,
                    End = end,
                    ViewName = $"g{baseAddr:x4}",
                    TypeName = $"ds_vars_{baseAddr:x4}",
                };

                // MC1 struct layout is positional, so we must emit padding bytes for gaps.
                // Build a contiguous layout from offset 0..maxOffInclusive.
                var maxAbs = chunk.Count == 0 ? baseAddr : chunk.Max();
                var maxOff = (ushort)(maxAbs - baseAddr);
                if (sizeByAddr.TryGetValue(maxAbs, out var maxSz) && maxSz == 2)
                    maxOff = (ushort)(maxOff + 1);

                ushort offCursor = 0;
                while (offCursor <= maxOff)
                {
                    var abs = (ushort)(baseAddr + offCursor);
                    var wantWord = sizeByAddr.TryGetValue(abs, out var sz) && sz == 2;

                    if (wantWord && offCursor + 1 <= maxOff)
                    {
                        v.Fields.Add((offCursor, $"w{offCursor:X2}", "u16"));
                        offCursor = (ushort)(offCursor + 2);
                        continue;
                    }

                    v.Fields.Add((offCursor, $"b{offCursor:X2}", "u8"));
                    offCursor = (ushort)(offCursor + 1);
                }

                views.Add(v);
            }

            return views;
        }

        private static bool TryParseU16(string hex4, out ushort value)
        {
            value = 0;
            var s = (hex4 ?? string.Empty).Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            return ushort.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        private static bool IsWordReg(string reg)
        {
            var r = (reg ?? string.Empty).Trim().ToLowerInvariant();
            return r is "ax" or "bx" or "cx" or "dx" or "si" or "di" or "bp" or "sp";
        }
    }
}
