using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    /// <summary>
    /// MC2 (Machine-C Level 2) is a higher-level sugar layer over MC1.
    ///
    /// Current implementation scope:
    /// - Enums (lowered to MC1 consts)
    /// - Regions (lowered to MC1 views + identifier rewriting)
    ///
    /// Byte-identity invariant:
    /// - In PreserveBytes mode, this lowering must not introduce new origin-bearing statements.
    ///   This implementation only emits declarations and rewrites tokens inside existing statement lines.
    /// </summary>
    public static class Mc2
    {
        public enum Mode
        {
            PreserveBytes,
            Canonical,
        }

        public sealed class Mc2File
        {
            [JsonPropertyName("source")]
            public string Source { get; set; }

            [JsonPropertyName("enums")]
            public List<EnumDecl> Enums { get; set; } = new();

            [JsonPropertyName("regions")]
            public List<RegionDecl> Regions { get; set; } = new();

            [JsonPropertyName("passthrough_lines")]
            public List<string> PassthroughLines { get; set; } = new();
        }

        public sealed class EnumDecl
        {
            public string Name { get; set; }
            public string BackingType { get; set; } // u8/u16/u32
            public List<(string Name, string ValueExpr)> Fields { get; set; } = new();
        }

        public sealed class RegionDecl
        {
            public string Name { get; set; }
            public string SegExpr { get; set; }
            public List<RegionField> Fields { get; set; } = new();
        }

        public sealed class RegionField
        {
            public string Name { get; set; }
            public string Type { get; set; }
            public string OffsetExpr { get; set; } // compile-time u16 const expr in spec; we keep as token
            public bool IsConst { get; set; }
        }

        private static readonly Regex CommentLineRx = new Regex(@"^\s*//", RegexOptions.Compiled);

        private static readonly Regex EnumStartRx = new Regex(
            @"^\s*enum\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?<ty>u8|u16|u32)\s*\{\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex EnumFieldRx = new Regex(
            @"^\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<val>[^;]+)\s*;\s*$",
            RegexOptions.Compiled);

        private static readonly Regex RegionStartRx = new Regex(
            @"^\s*region\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s+in\s+(?<seg>[^\{;]+)\s*\{\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex RegionFieldRx = new Regex(
            @"^\s*(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?<ty>[A-Za-z_][A-Za-z0-9_]*)\s+at\s+(?<off>[^;]+?)(?<const>\s+const)?\s*;\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex BlockEndRx = new Regex(@"^\s*\}\s*;\s*$", RegexOptions.Compiled);

        public static Mc2File Parse(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Missing path", nameof(path));
            if (!File.Exists(path)) throw new FileNotFoundException("MC2 file not found", path);
            return ParseLines(File.ReadAllLines(path), path);
        }

        public static Mc2File ParseLines(IReadOnlyList<string> lines, string sourceName = null)
        {
            if (lines == null) throw new ArgumentNullException(nameof(lines));

            var file = new Mc2File { Source = sourceName ?? string.Empty };

            for (var i = 0; i < lines.Count; i++)
            {
                var line = lines[i] ?? string.Empty;
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) { file.PassthroughLines.Add(line); continue; }
                if (CommentLineRx.IsMatch(trimmed)) { file.PassthroughLines.Add(line); continue; }

                var mEnum = EnumStartRx.Match(line);
                if (mEnum.Success)
                {
                    var e = new EnumDecl
                    {
                        Name = mEnum.Groups["name"].Value,
                        BackingType = mEnum.Groups["ty"].Value.ToLowerInvariant(),
                    };

                    i++;
                    for (; i < lines.Count; i++)
                    {
                        var l = lines[i] ?? string.Empty;
                        var t = l.Trim();
                        if (string.IsNullOrWhiteSpace(t)) continue;
                        if (CommentLineRx.IsMatch(t)) continue;
                        if (BlockEndRx.IsMatch(l)) break;

                        var mf = EnumFieldRx.Match(l);
                        if (!mf.Success)
                            throw new InvalidDataException($"Invalid enum field on line {i + 1}: '{l}'");

                        e.Fields.Add((mf.Groups["name"].Value, mf.Groups["val"].Value.Trim()));
                    }

                    if (e.Fields.Count == 0)
                        throw new InvalidDataException($"Empty enum '{e.Name}'");

                    file.Enums.Add(e);
                    continue;
                }

                var mRegion = RegionStartRx.Match(line);
                if (mRegion.Success)
                {
                    var r = new RegionDecl
                    {
                        Name = mRegion.Groups["name"].Value,
                        SegExpr = mRegion.Groups["seg"].Value.Trim(),
                    };

                    i++;
                    for (; i < lines.Count; i++)
                    {
                        var l = lines[i] ?? string.Empty;
                        var t = l.Trim();
                        if (string.IsNullOrWhiteSpace(t)) continue;
                        if (CommentLineRx.IsMatch(t)) continue;
                        if (BlockEndRx.IsMatch(l)) break;

                        var mf = RegionFieldRx.Match(l);
                        if (!mf.Success)
                            throw new InvalidDataException($"Invalid region field on line {i + 1}: '{l}'");

                        r.Fields.Add(new RegionField
                        {
                            Name = mf.Groups["name"].Value,
                            Type = mf.Groups["ty"].Value,
                            OffsetExpr = mf.Groups["off"].Value.Trim(),
                            IsConst = !string.IsNullOrWhiteSpace(mf.Groups["const"].Value),
                        });
                    }

                    if (r.Fields.Count == 0)
                        throw new InvalidDataException($"Empty region '{r.Name}'");

                    file.Regions.Add(r);
                    continue;
                }

                file.PassthroughLines.Add(line);
            }

            return file;
        }

        public static string DesugarToMc1Text(Mc2File mc2, Mode mode)
        {
            if (mc2 == null) throw new ArgumentNullException(nameof(mc2));

            // Emit MC1 text: declarations first (deterministic order), then rewritten body.
            var sb = new StringBuilder();
            sb.AppendLine("// MC1 desugared from MC2 by DOSRE");
            if (!string.IsNullOrWhiteSpace(mc2.Source)) sb.AppendLine($"// source: {mc2.Source}");
            sb.AppendLine();

            // Enums -> consts
            foreach (var e in mc2.Enums.OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                foreach (var f in e.Fields)
                {
                    var constName = $"{e.Name}_{f.Name}";
                    sb.AppendLine($"const {constName}: {e.BackingType} = {f.ValueExpr};");
                }
                sb.AppendLine();
            }

            // Regions -> views
            var regionFieldInfo = new Dictionary<string, (string viewName, bool isConst)>(StringComparer.Ordinal);
            foreach (var r in mc2.Regions.OrderBy(x => x.Name, StringComparer.Ordinal))
            {
                foreach (var f in r.Fields.OrderBy(x => x.Name, StringComparer.Ordinal))
                {
                    var viewName = $"_r_{r.Name}_{f.Name}";
                    regionFieldInfo[$"{r.Name}.{f.Name}"] = (viewName, f.IsConst);
                    sb.AppendLine($"view {viewName} at ({r.SegExpr}, {f.OffsetExpr}) : {f.Type};");
                }
                sb.AppendLine();
            }

            // Body: rewrite enum refs and region refs.
            // Note: this implementation keeps origin-bearing statement lines 1:1; it only rewrites token text.
            foreach (var raw in mc2.PassthroughLines)
            {
                var line = raw ?? string.Empty;
                var rewritten = line;

                // Replace Enum tags with generated const names when referenced as E.Tag
                foreach (var e in mc2.Enums)
                {
                    foreach (var f in e.Fields)
                    {
                        var from = $"{e.Name}.{f.Name}";
                        var to = $"{e.Name}_{f.Name}";
                        rewritten = Regex.Replace(rewritten,
                            $@"\b{Regex.Escape(from)}\b",
                            to);
                    }
                }

                // Enforce const region fields on simple assignment patterns.
                // (We intentionally stay conservative; complex writes may not be caught here.)
                foreach (var kv in regionFieldInfo)
                {
                    var from = kv.Key;
                    var (to, isConst) = kv.Value;

                    if (isConst)
                    {
                        var assignRx = new Regex($@"\b{Regex.Escape(from)}\b\s*=" , RegexOptions.Compiled);
                        if (assignRx.IsMatch(rewritten))
                            throw new InvalidDataException($"Write to const region field '{from}' is not allowed.");
                    }

                    rewritten = Regex.Replace(rewritten,
                        $@"\b{Regex.Escape(from)}\b",
                        to);
                }

                sb.AppendLine(rewritten);
            }

            return sb.ToString();
        }

        internal static uint ParseUInt(string tok)
        {
            if (string.IsNullOrWhiteSpace(tok)) throw new InvalidDataException("Empty integer literal");
            var t = tok.Trim();
            if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return uint.Parse(t.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (t.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                return uint.Parse(t.Substring(0, t.Length - 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return uint.Parse(t, NumberStyles.Integer, CultureInfo.InvariantCulture);
        }
    }
}
