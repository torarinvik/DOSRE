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
            /// Lift simple absolute ES memory loads/stores into views.
            /// Defaults to a small low-memory window (0x0000..0x00FF).
            /// </summary>
            public bool LiftEsAbsoluteGlobals { get; set; } = true;

            /// <summary>
            /// Lift absolute reads/writes from segment 0 (0000:XXXX) into farptr16 views.
            /// This is useful for interrupt vector table style accesses.
            /// </summary>
            public bool LiftIvtFarptrViews { get; set; } = true;

            /// <summary>
            /// Lift simple DS indexed movs like [ds:bx+di+0xNNNN] into primitive views using MC1 bracket sugar.
            /// </summary>
            public bool LiftDsIndexedGlobals { get; set; } = true;

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

            /// <summary>
            /// Max size of a generated ES view window, in bytes.
            /// </summary>
            public ushort EsViewMaxSpan { get; set; } = 0x0040;

            /// <summary>
            /// Only lift absolute ES addresses in this inclusive range.
            /// </summary>
            public ushort EsAbsMin { get; set; } = 0x0000;
            public ushort EsAbsMax { get; set; } = 0x00FF;

            /// <summary>
            /// Only lift IVT (segment 0) offsets in this inclusive range.
            /// Default is the classic IVT window (0x0000..0x03FF).
            /// </summary>
            public ushort IvtOffMin { get; set; } = 0x0000;
            public ushort IvtOffMax { get; set; } = 0x03FF;
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

        // Matches: mov ax, [ds:0x04E4]
        //          mov ax, [es:0070h]
        //          mov al, [0AF0Ah]
        private static readonly Regex MovLoadRx = new Regex(
            @"^\s*mov\s+(?<dst>[a-z]{2})\s*,\s*\[(?:(?<seg>cs|ds|es|ss)\s*:\s*)?(?<addr>(?:0x)?[0-9A-Fa-f]{1,5})h?\]\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Matches: mov [ds:0x04EC], ax
        //          mov [es:72h], ds
        private static readonly Regex MovStoreRx = new Regex(
            @"^\s*mov\s+\[(?:(?<seg>cs|ds|es|ss)\s*:\s*)?(?<addr>(?:0x)?[0-9A-Fa-f]{1,5})h?\]\s*,\s*(?<src>[a-z]{2})\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Matches: mov ax, [0000h:0084h]
        //          mov [0x0000:0x0086], ax
        private static readonly Regex MovSegConstLoadRx = new Regex(
            @"^\s*mov\s+(?<dst>[a-z]{2})\s*,\s*\[(?<seg>(?:0x)?[0-9A-Fa-f]{1,4})h?\s*:\s*(?<off>(?:0x)?[0-9A-Fa-f]{1,5})h?\]\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovSegConstStoreRx = new Regex(
            @"^\s*mov\s+\[(?<seg>(?:0x)?[0-9A-Fa-f]{1,4})h?\s*:\s*(?<off>(?:0x)?[0-9A-Fa-f]{1,5})h?\]\s*,\s*(?<src>[a-z]{2})\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Matches: mov ax, [ds:bx+di+04E4h]
        //          mov [ds:bx+di+04ECh], ax
        private static readonly Regex MovDsIndexedLoadRx = new Regex(
            @"^\s*mov\s+(?<dst>[a-z]{2})\s*,\s*\[(?:ds\s*:\s*)?(?<ea>[^\]]+)\]\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MovDsIndexedStoreRx = new Regex(
            @"^\s*mov\s+\[(?:ds\s*:\s*)?(?<ea>[^\]]+)\]\s*,\s*(?<src>[a-z]{2})\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Generic binary ops involving a memory operand (used for bracket sugar).
        // Examples:
        //   or ax, [ds:bx+di]
        //   and [cs:bx+si+72h], dl
        private static readonly Regex BinOpRegMemRx = new Regex(
            @"^\s*(?<op>add|adc|and|cmp|or|sbb|sub|xor)\s+(?<dst>[a-z]{2})\s*,\s*\[(?:(?<seg>cs|ds|es|ss)\s*:\s*)?(?<ea>[^\]]+)\]\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex BinOpMemRegRx = new Regex(
            @"^\s*(?<op>add|adc|and|cmp|or|sbb|sub|xor)\s+\[(?:(?<seg>cs|ds|es|ss)\s*:\s*)?(?<ea>[^\]]+)\]\s*,\s*(?<src>[a-z]{2})\s*$",
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
            { "cs", "CS" }, { "ds", "DS" }, { "es", "ES" }, { "ss", "SS" },
        };

        private sealed class SegAbsAccess
        {
            public string Seg;
            public ushort Addr;
            public int Size;
            public string Reg;
            public bool IsStore;
        }

        private sealed class IvtWordAccess
        {
            public ushort Off;
            public string Reg;
            public bool IsStore;
        }

        private sealed class PrimView
        {
            public string ViewName;
            public string Seg;
            public ushort Base;
            public string ElemType;

            public string RenderViewDecl() => $"view {ViewName} at ({Seg}, 0x{Base:X4}) : {ElemType};";
        }

        private sealed class SegView
        {
            public string Seg;
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

            public string RenderViewDecl() => $"view {ViewName} at ({Seg}, 0x{Base:X4}) : {TypeName};";
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

            // Phase 1: collect potential rewrites.
            var neededIntConsts = new SortedDictionary<string, ushort>(StringComparer.Ordinal);
            var segAccesses = new List<SegAbsAccess>();
            var ivtAccesses = new List<IvtWordAccess>();
            var primViews = new SortedDictionary<string, PrimView>(StringComparer.Ordinal);

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

                if (opts.LiftIvtFarptrViews)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(asm))
                    {
                        var mSegLoad = MovSegConstLoadRx.Match(asm);
                        if (mSegLoad.Success)
                        {
                            var dst = mSegLoad.Groups["dst"].Value;
                            var segTok = mSegLoad.Groups["seg"].Value;
                            var offTok = mSegLoad.Groups["off"].Value;
                            if (TryParseU16Flexible(segTok, out var segVal) && segVal == 0 && TryParseU16Flexible(offTok, out var off))
                            {
                                if (off >= opts.IvtOffMin && off <= opts.IvtOffMax && IsWordReg(dst) && RegMap.TryGetValue(dst, out var reg))
                                {
                                    ivtAccesses.Add(new IvtWordAccess { Off = off, Reg = reg, IsStore = false });
                                    continue;
                                }
                            }
                        }

                        var mSegStore = MovSegConstStoreRx.Match(asm);
                        if (mSegStore.Success)
                        {
                            var src = mSegStore.Groups["src"].Value;
                            var segTok = mSegStore.Groups["seg"].Value;
                            var offTok = mSegStore.Groups["off"].Value;
                            if (TryParseU16Flexible(segTok, out var segVal) && segVal == 0 && TryParseU16Flexible(offTok, out var off))
                            {
                                if (off >= opts.IvtOffMin && off <= opts.IvtOffMax && IsWordReg(src) && RegMap.TryGetValue(src, out var reg))
                                {
                                    ivtAccesses.Add(new IvtWordAccess { Off = off, Reg = reg, IsStore = true });
                                    continue;
                                }
                            }
                        }
                    }
                }

                if (opts.LiftDsAbsoluteGlobals || opts.LiftEsAbsoluteGlobals || opts.LiftDsIndexedGlobals)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(asm)) continue;

                    if (opts.LiftDsIndexedGlobals)
                    {
                        // Collect primitive views needed for non-mov memory ops too.
                        var mOpRegMem = BinOpRegMemRx.Match(asm);
                        if (mOpRegMem.Success)
                        {
                            var segTok = (mOpRegMem.Groups["seg"].Success ? mOpRegMem.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();
                            var ea = mOpRegMem.Groups["ea"].Value;
                            var dst = mOpRegMem.Groups["dst"].Value;

                            // Memory width follows the register width.
                            var size = IsWordReg(dst) ? 2 : 1;
                            if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: true))
                                _ = GetOrCreatePrimViewAndIndex(segTok, immSum, regs, size, primViews);
                        }
                        else
                        {
                            var mOpMemReg = BinOpMemRegRx.Match(asm);
                            if (mOpMemReg.Success)
                            {
                                var segTok = (mOpMemReg.Groups["seg"].Success ? mOpMemReg.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();
                                var ea = mOpMemReg.Groups["ea"].Value;
                                var src = mOpMemReg.Groups["src"].Value;

                                var size = IsWordReg(src) ? 2 : 1;
                                if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: true))
                                    _ = GetOrCreatePrimViewAndIndex(segTok, immSum, regs, size, primViews);
                            }
                        }
                    }

                    // Only lift simple mov loads/stores for now.
                    var mLoad = MovLoadRx.Match(asm);
                    if (mLoad.Success)
                    {
                        var dst = mLoad.Groups["dst"].Value;
                        var segTok = (mLoad.Groups["seg"].Success ? mLoad.Groups["seg"].Value : "ds").Trim();
                        var addrTok = mLoad.Groups["addr"].Value;
                        if (!TryParseU16Flexible(addrTok, out var addr)) continue;
                        if (!ShouldLiftAbsSeg(segTok, addr, opts)) continue;
                        if (!RegMap.TryGetValue(dst, out var reg)) continue;
                        var size = IsWordReg(dst) ? 2 : 1;
                        segAccesses.Add(new SegAbsAccess { Seg = segTok.ToUpperInvariant(), Addr = addr, Size = size, Reg = reg, IsStore = false });
                        continue;
                    }

                    var mStore = MovStoreRx.Match(asm);
                    if (mStore.Success)
                    {
                        var src = mStore.Groups["src"].Value;
                        var segTok = (mStore.Groups["seg"].Success ? mStore.Groups["seg"].Value : "ds").Trim();
                        var addrTok = mStore.Groups["addr"].Value;
                        if (!TryParseU16Flexible(addrTok, out var addr)) continue;
                        if (!ShouldLiftAbsSeg(segTok, addr, opts)) continue;
                        if (!RegMap.TryGetValue(src, out var reg)) continue;
                        var size = IsWordReg(src) ? 2 : 1;
                        segAccesses.Add(new SegAbsAccess { Seg = segTok.ToUpperInvariant(), Addr = addr, Size = size, Reg = reg, IsStore = true });
                        continue;
                    }

                    if (opts.LiftDsIndexedGlobals)
                    {
                        // Load: mov r, [ds:ea]
                        var mIdxLoad = MovDsIndexedLoadRx.Match(asm);
                        if (mIdxLoad.Success)
                        {
                            var dst = mIdxLoad.Groups["dst"].Value;
                            var ea = mIdxLoad.Groups["ea"].Value;
                            if (!RegMap.TryGetValue(dst, out var reg))
                                continue;
                            var size = IsWordReg(dst) ? 2 : 1;
                            if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: false) && immSum >= opts.DsAbsMin && immSum <= opts.DsAbsMax)
                            {
                                _ = GetOrCreatePrimViewAndIndex("DS", immSum, regs, size, primViews);
                                // Record rewrite via a synthetic access entry in segAccesses? We'll just rewrite later.
                            }
                        }

                        // Store: mov [ds:ea], r
                        var mIdxStore = MovDsIndexedStoreRx.Match(asm);
                        if (mIdxStore.Success)
                        {
                            var src = mIdxStore.Groups["src"].Value;
                            var ea = mIdxStore.Groups["ea"].Value;
                            if (!RegMap.TryGetValue(src, out var reg))
                                continue;
                            var size = IsWordReg(src) ? 2 : 1;
                            if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: false) && immSum >= opts.DsAbsMin && immSum <= opts.DsAbsMax)
                            {
                                _ = GetOrCreatePrimViewAndIndex("DS", immSum, regs, size, primViews);
                            }
                        }
                    }
                }
            }

            // Phase 2: build view(s) for collected absolute addresses.
            var segViews = BuildSegViews(segAccesses, opts);
            var viewBySegAddr = new Dictionary<(string seg, ushort addr), (string view, string field)>(segAccesses.Count);

            foreach (var v in segViews)
            {
                foreach (var f in v.Fields)
                {
                    var off = f.Off;
                    var abs = (ushort)(v.Base + off);
                    viewBySegAddr[(v.Seg, abs)] = (v.ViewName, f.Name);
                }
            }

            // Phase 2b: IVT farptr views for segment 0.
            var ivtViewsByBase = new SortedDictionary<ushort, string>();
            if (opts.LiftIvtFarptrViews && ivtAccesses.Count > 0)
            {
                foreach (var a in ivtAccesses)
                {
                    var baseOff = (ushort)(a.Off & 0xFFFC);
                    var mod = (ushort)(a.Off - baseOff);
                    if (mod != 0 && mod != 2)
                        continue;
                    if (!ivtViewsByBase.ContainsKey(baseOff))
                        ivtViewsByBase[baseOff] = $"ivt_{(baseOff / 4):X2}";
                }
            }

            // Phase 3: emit MC1 text.
            var sb = new StringBuilder();
            sb.AppendLine("// mc1 lifted from mc0");
            if (!string.IsNullOrWhiteSpace(mc0.Source)) sb.AppendLine($"// source: {mc0.Source}");
            if (!string.IsNullOrWhiteSpace(mc0.StreamSha256)) sb.AppendLine($"// stream_sha256: {mc0.StreamSha256}");
            sb.AppendLine("// format: <stmt>; // @AAAAAAAA HEXBYTES ; original asm");
            sb.AppendLine();

            if (neededIntConsts.Count > 0 || segViews.Count > 0 || ivtViewsByBase.Count > 0 || primViews.Count > 0)
            {
                sb.AppendLine("// ---- MC1 declarations (auto) ----");
                if (neededIntConsts.Count > 0)
                {
                    sb.AppendLine("// Interrupt vectors:");
                    foreach (var kv in neededIntConsts)
                        sb.AppendLine($"const {kv.Key}: u16 = 0x{kv.Value:X4};");
                    sb.AppendLine();
                }

                if (segViews.Count > 0)
                {
                    sb.AppendLine("// Absolute globals (auto-lifted views):");
                    foreach (var v in segViews)
                    {
                        sb.AppendLine(v.RenderTypeDecl());
                        sb.AppendLine(v.RenderViewDecl());
                        sb.AppendLine();
                    }
                }

                if (primViews.Count > 0)
                {
                    sb.AppendLine("// DS indexed globals (primitive views for bracket sugar):");
                    foreach (var pv in primViews.Values)
                        sb.AppendLine(pv.RenderViewDecl());
                    sb.AppendLine();
                }

                if (ivtViewsByBase.Count > 0)
                {
                    sb.AppendLine("// IVT far pointers (segment 0):");
                    foreach (var kv in ivtViewsByBase)
                        sb.AppendLine($"view {kv.Value} at (0x0000, 0x{kv.Key:X4}) : farptr16;");
                    sb.AppendLine();
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

                // Rewrite segment-constant 0000:XXXX accesses into IVT farptr views.
                if (opts.LiftIvtFarptrViews && ivtViewsByBase.Count > 0)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(asm))
                    {
                        var mSegLoad = MovSegConstLoadRx.Match(asm);
                        if (mSegLoad.Success)
                        {
                            var dst = mSegLoad.Groups["dst"].Value;
                            var segTok = mSegLoad.Groups["seg"].Value;
                            var offTok = mSegLoad.Groups["off"].Value;
                            if (TryParseU16Flexible(segTok, out var segVal) && segVal == 0 && TryParseU16Flexible(offTok, out var off) && RegMap.TryGetValue(dst, out var reg))
                            {
                                var baseOff = (ushort)(off & 0xFFFC);
                                var mod = (ushort)(off - baseOff);
                                if (ivtViewsByBase.TryGetValue(baseOff, out var viewName) && (mod == 0 || mod == 2))
                                {
                                    var field = mod == 0 ? "off" : "seg";
                                    stmtText = $"{reg} = {viewName}.{field}";
                                }
                            }
                        }
                        else
                        {
                            var mSegStore = MovSegConstStoreRx.Match(asm);
                            if (mSegStore.Success)
                            {
                                var src = mSegStore.Groups["src"].Value;
                                var segTok = mSegStore.Groups["seg"].Value;
                                var offTok = mSegStore.Groups["off"].Value;
                                if (TryParseU16Flexible(segTok, out var segVal) && segVal == 0 && TryParseU16Flexible(offTok, out var off) && RegMap.TryGetValue(src, out var reg))
                                {
                                    var baseOff = (ushort)(off & 0xFFFC);
                                    var mod = (ushort)(off - baseOff);
                                    if (ivtViewsByBase.TryGetValue(baseOff, out var viewName) && (mod == 0 || mod == 2))
                                    {
                                        var field = mod == 0 ? "off" : "seg";
                                        stmtText = $"{viewName}.{field} = {reg}";
                                    }
                                }
                            }
                        }
                    }
                }

                // Rewrite absolute movs into view.field when possible.
                if (opts.LiftDsAbsoluteGlobals || opts.LiftEsAbsoluteGlobals)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();

                    var mLoad = MovLoadRx.Match(asm);
                    if (mLoad.Success)
                    {
                        var dst = mLoad.Groups["dst"].Value;
                        var segTok = (mLoad.Groups["seg"].Success ? mLoad.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();
                        var addrTok = mLoad.Groups["addr"].Value;
                        if (TryParseU16Flexible(addrTok, out var addr) && viewBySegAddr.TryGetValue((segTok, addr), out var vf) && RegMap.TryGetValue(dst, out var reg))
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
                            var segTok = (mStore.Groups["seg"].Success ? mStore.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();
                            var addrTok = mStore.Groups["addr"].Value;
                            if (TryParseU16Flexible(addrTok, out var addr) && viewBySegAddr.TryGetValue((segTok, addr), out var vf) && RegMap.TryGetValue(src, out var reg))
                            {
                                stmtText = $"{vf.view}.{vf.field} = {reg}";
                            }
                        }
                    }
                }

                // Rewrite DS indexed movs into primitive view[idx] when possible.
                if (opts.LiftDsIndexedGlobals && primViews.Count > 0)
                {
                    var asm = (st.Asm ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(asm))
                    {
                        // First: non-mov memory ops (keep semantics opaque; only sugar the memory operand).
                        var mOpRegMem = BinOpRegMemRx.Match(asm);
                        if (mOpRegMem.Success)
                        {
                            var op = mOpRegMem.Groups["op"].Value.Trim().ToUpperInvariant();
                            var dst = mOpRegMem.Groups["dst"].Value;
                            var ea = mOpRegMem.Groups["ea"].Value;
                            var segTok = (mOpRegMem.Groups["seg"].Success ? mOpRegMem.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();

                            if (RegMap.TryGetValue(dst, out var reg))
                            {
                                var size = IsWordReg(dst) ? 2 : 1;
                                if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: true))
                                {
                                    var (viewName, idxExpr) = GetOrCreatePrimViewAndIndex(segTok, immSum, regs, size, primViews);
                                    stmtText = $"{reg} = {op}({reg}, {viewName}[{idxExpr}])";
                                }
                            }
                        }
                        else
                        {
                            var mOpMemReg = BinOpMemRegRx.Match(asm);
                            if (mOpMemReg.Success)
                            {
                                var op = mOpMemReg.Groups["op"].Value.Trim().ToUpperInvariant();
                                var src = mOpMemReg.Groups["src"].Value;
                                var ea = mOpMemReg.Groups["ea"].Value;
                                var segTok = (mOpMemReg.Groups["seg"].Success ? mOpMemReg.Groups["seg"].Value : "ds").Trim().ToUpperInvariant();

                                if (RegMap.TryGetValue(src, out var reg))
                                {
                                    var size = IsWordReg(src) ? 2 : 1;
                                    if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: true))
                                    {
                                        var (viewName, idxExpr) = GetOrCreatePrimViewAndIndex(segTok, immSum, regs, size, primViews);
                                        // This becomes a STORE during MC1 desugar.
                                        stmtText = $"{viewName}[{idxExpr}] = {op}({viewName}[{idxExpr}], {reg})";
                                    }
                                }
                            }
                        }

                        var mIdxLoad = MovDsIndexedLoadRx.Match(asm);
                        if (mIdxLoad.Success)
                        {
                            var dst = mIdxLoad.Groups["dst"].Value;
                            var ea = mIdxLoad.Groups["ea"].Value;
                            if (RegMap.TryGetValue(dst, out var reg))
                            {
                                var size = IsWordReg(dst) ? 2 : 1;
                                if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: false) && immSum >= opts.DsAbsMin && immSum <= opts.DsAbsMax)
                                {
                                    var (viewName, idxExpr) = GetOrCreatePrimViewAndIndex("DS", immSum, regs, size, primViews);
                                    stmtText = $"{reg} = {viewName}[{idxExpr}]";
                                }
                            }
                        }
                        else
                        {
                            var mIdxStore = MovDsIndexedStoreRx.Match(asm);
                            if (mIdxStore.Success)
                            {
                                var src = mIdxStore.Groups["src"].Value;
                                var ea = mIdxStore.Groups["ea"].Value;
                                if (RegMap.TryGetValue(src, out var reg))
                                {
                                    var size = IsWordReg(src) ? 2 : 1;
                                    if (TryParseIndexedEa(ea, out var immSum, out var regs, allowNoImmediate: false) && immSum >= opts.DsAbsMin && immSum <= opts.DsAbsMax)
                                    {
                                        var (viewName, idxExpr) = GetOrCreatePrimViewAndIndex("DS", immSum, regs, size, primViews);
                                        stmtText = $"{viewName}[{idxExpr}] = {reg}";
                                    }
                                }
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

        private static List<SegView> BuildSegViews(List<SegAbsAccess> accesses, LiftOptions opts)
        {
            if (accesses == null || accesses.Count == 0) return new List<SegView>();

            var bySeg = accesses
                .GroupBy(a => (a.Seg ?? string.Empty).Trim().ToUpperInvariant(), StringComparer.Ordinal)
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .ToList();

            var allViews = new List<SegView>();
            foreach (var segGroup in bySeg)
            {
                var seg = segGroup.Key;
                var maxSpan = GetViewMaxSpan(seg, opts);

                // Deduplicate addresses and decide whether each address is word or byte.
                var sizeByAddr = new Dictionary<ushort, int>();
                foreach (var a in segGroup)
                {
                    if (!sizeByAddr.TryGetValue(a.Addr, out var sz) || a.Size > sz)
                        sizeByAddr[a.Addr] = a.Size;
                }

                var addrs = sizeByAddr.Keys.OrderBy(x => x).ToList();
                var i = 0;
                while (i < addrs.Count)
                {
                    var first = addrs[i];
                    var baseAddr = (ushort)(first & 0xFFF0);
                    var end = (ushort)(baseAddr + maxSpan - 1);

                    // Pull in all addresses within the window.
                    var chunk = new List<ushort>();
                    while (i < addrs.Count && addrs[i] <= end)
                    {
                        chunk.Add(addrs[i]);
                        i++;
                    }

                    var (viewName, typeName) = MakeNames(seg, baseAddr);
                    var v = new SegView
                    {
                        Seg = seg,
                        Base = baseAddr,
                        End = end,
                        ViewName = viewName,
                        TypeName = typeName,
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

                    allViews.Add(v);
                }
            }

            return allViews;
        }

        private static bool ShouldLiftAbsSeg(string segTok, ushort addr, LiftOptions opts)
        {
            var seg = (segTok ?? string.Empty).Trim().ToUpperInvariant();
            return seg switch
            {
                "DS" => opts.LiftDsAbsoluteGlobals && addr >= opts.DsAbsMin && addr <= opts.DsAbsMax,
                "ES" => opts.LiftEsAbsoluteGlobals && addr >= opts.EsAbsMin && addr <= opts.EsAbsMax,
                _ => false,
            };
        }

        private static ushort GetViewMaxSpan(string seg, LiftOptions opts)
        {
            return seg switch
            {
                "DS" => opts.DsViewMaxSpan,
                "ES" => opts.EsViewMaxSpan,
                _ => opts.DsViewMaxSpan,
            };
        }

        private static (string viewName, string typeName) MakeNames(string seg, ushort baseAddr)
        {
            var s = (seg ?? string.Empty).Trim().ToUpperInvariant();
            if (s == "DS")
                return ($"g{baseAddr:x4}", $"ds_vars_{baseAddr:x4}");
            return ($"{s.ToLowerInvariant()}_g{baseAddr:x4}", $"{s.ToLowerInvariant()}_vars_{baseAddr:x4}");
        }

        private static bool TryParseU16Flexible(string token, out ushort value)
        {
            value = 0;
            var s = (token ?? string.Empty).Trim();
            if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(0, s.Length - 1);
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);
            if (s.Length == 0 || s.Length > 5)
                return false;
            if (!uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var tmp))
                return false;
            if (tmp > 0xFFFF)
                return false;
            value = (ushort)tmp;
            return true;
        }

        private static bool IsWordReg(string reg)
        {
            var r = (reg ?? string.Empty).Trim().ToLowerInvariant();
            return r is "ax" or "bx" or "cx" or "dx" or "si" or "di" or "bp" or "sp" or "cs" or "ds" or "es" or "ss";
        }

        private static bool TryParseIndexedEa(string ea, out ushort immSum, out List<string> regs, bool allowNoImmediate)
        {
            immSum = 0;
            regs = new List<string>();

            var s = (ea ?? string.Empty).Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(s))
                return false;

            // Remove whitespace to make splitting stable.
            s = new string(s.Where(c => !char.IsWhiteSpace(c)).ToArray());

            // Only handle '+' addressing for now.
            var parts = s.Split(new[] { '+' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return false;

            uint immAcc = 0;
            foreach (var pRaw in parts)
            {
                var p = pRaw.Trim();
                if (p is "bx" or "bp" or "si" or "di")
                {
                    regs.Add(p.ToUpperInvariant());
                    continue;
                }

                if (TryParseU16Flexible(p, out var imm))
                {
                    immAcc += imm;
                    if (immAcc > 0xFFFF)
                        return false;
                    continue;
                }

                // Unknown token (scale, minus, etc)
                return false;
            }

            if (regs.Count == 0)
                return false;
            if (!allowNoImmediate && immAcc == 0)
                return false;

            immSum = (ushort)immAcc;
            return true;
        }

        private static (string viewName, string idxExpr) GetOrCreatePrimViewAndIndex(
            string seg,
            ushort immSum,
            List<string> regs,
            int size,
            SortedDictionary<string, PrimView> primViews)
        {
            var baseAligned = (ushort)(immSum == 0 ? 0 : (immSum & 0xFFF0));
            var delta = (ushort)(immSum - baseAligned);

            // Build register sum expression.
            string idx = null;
            foreach (var r in regs)
            {
                idx = idx == null ? r : $"ADD16({idx}, {r})";
            }

            if (delta != 0)
                idx = $"ADD16({idx}, 0x{delta:X4})";

            var elemType = size == 1 ? "u8" : "u16";
            var s = (seg ?? string.Empty).Trim().ToUpperInvariant();
            var viewName = $"mem_{s.ToLowerInvariant()}_{baseAligned:x4}_{(size == 1 ? "b" : "w")}";
            if (!primViews.ContainsKey(viewName))
            {
                primViews[viewName] = new PrimView
                {
                    ViewName = viewName,
                    Seg = s,
                    Base = baseAligned,
                    ElemType = elemType,
                };
            }

            return (viewName, idx);
        }
    }
}
