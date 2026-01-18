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
    /// MC1 (Machine-C Level 1) is a deterministic, declarative sugar layer over MC0.
    ///
    /// Important constraint for "byte-equal + verifiable" workflows:
    /// - MC1 desugars to MC0 without introducing new origin-bearing statements.
    /// - MC1 may introduce *declarations* (types/consts/views) and expression sugar that rewrites within
    ///   existing origin statements.
    ///
    /// So MC1's meaning is defined purely as: Exec(MC1) == Exec(DesugarToMc0(MC1)).
    /// </summary>
    public static class Mc1
    {
        public sealed class Mc1File
        {
            [JsonPropertyName("source")]
            public string Source { get; set; }

            [JsonPropertyName("types")]
            public Dictionary<string, StructType> Types { get; set; } = new(StringComparer.Ordinal);

            [JsonPropertyName("consts")]
            public Dictionary<string, ConstValue> Consts { get; set; } = new(StringComparer.Ordinal);

            [JsonPropertyName("views")]
            public Dictionary<string, ViewDecl> Views { get; set; } = new(StringComparer.Ordinal);

            [JsonPropertyName("statements")]
            public List<string> Statements { get; set; } = new();
        }

        public sealed class StructType
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }

            [JsonPropertyName("fields")]
            public List<Field> Fields { get; set; } = new();
        }

        public sealed class Field
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }

            [JsonPropertyName("type")]
            public string Type { get; set; }
        }

        public sealed class ConstValue
        {
            [JsonPropertyName("type")]
            public string Type { get; set; }

            [JsonPropertyName("value")]
            public uint Value { get; set; }
        }

        public sealed class ViewDecl
        {
            [JsonPropertyName("name")]
            public string Name { get; set; }

            [JsonPropertyName("seg")]
            public string SegExpr { get; set; }

            [JsonPropertyName("off")]
            public string OffExpr { get; set; }

            [JsonPropertyName("type")]
            public string Type { get; set; }
        }

        private static readonly Regex TypeDeclRx = new Regex(
            @"^\s*type\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*struct\s*\{\s*(?<body>.*)\s*\}\s*;\s*$",
            RegexOptions.Compiled);

        private static readonly Regex FieldRx = new Regex(
            @"(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?<type>[A-Za-z_][A-Za-z0-9_]*)\s*;",
            RegexOptions.Compiled);

        private static readonly Regex ConstDeclRx = new Regex(
            @"^\s*const\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?<type>u8|u16|u32|bool)\s*=\s*(?<val>[^;]+)\s*;\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex ViewDeclRx = new Regex(
            @"^\s*view\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s+at\s*\(\s*(?<seg>[^,]+)\s*,\s*(?<off>[^\)]+)\s*\)\s*:\s*(?<type>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex CommentLineRx = new Regex(@"^\s*//", RegexOptions.Compiled);

        // view.field (simple token form; no parentheses support yet)
        private static readonly Regex ViewFieldRx = new Regex(
            @"\b(?<view>[A-Za-z_][A-Za-z0-9_]*)\.(?<field>[A-Za-z_][A-Za-z0-9_]*)\b",
            RegexOptions.Compiled);

        // view.field = rhs; (rewritten to STOREn(seg, off, rhs);)
        private static readonly Regex ViewFieldStoreRx = new Regex(
            @"\b(?<view>[A-Za-z_][A-Za-z0-9_]*)\.(?<field>[A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*(?<rhs>[^;]+)\s*;",
            RegexOptions.Compiled);

        // view[idx] (primitive views only; rewritten to LOADn(seg, ADD16(off, idx)))
        private static readonly Regex ViewIndexRx = new Regex(
            @"\b(?<view>[A-Za-z_][A-Za-z0-9_]*)\[(?<idx>[^\]]+)\]",
            RegexOptions.Compiled);

        // view[idx] = rhs; (primitive views only; rewritten to STOREn(seg, ADD16(off, idx), rhs);)
        private static readonly Regex ViewIndexStoreRx = new Regex(
            @"\b(?<view>[A-Za-z_][A-Za-z0-9_]*)\[(?<idx>[^\]]+)\]\s*=\s*(?<rhs>[^;]+)\s*;",
            RegexOptions.Compiled);

        // Parse an origin-tagged statement line, preserving the comment verbatim.
        private static readonly Regex Mc0LineRx = new Regex(
            @"^(?<indent>\s*)(?<stmt>.*?);\s*//\s*(?<comment>.*)$",
            RegexOptions.Compiled);

        // Asm-like MC1 sugar:
        //   AND AX, mem_ds_0000_w[ADD16(BX, DI)];
        //   AND mem_ds_0020_b[ADD16(DI, 0x0002)], DH;
        //   CMP AX, mem_ds_0000_w[ADD16(BX, DI)];
        //   INC AX;  /  DEC AX;
        //   AX++;    /  AX--;
        // Lowers to:
        //   AX = AND(AX, ...);
        //   mem[...] = AND(mem[...], DH);
        private static readonly Regex MnemonicBinOpRx = new Regex(
            @"^\s*(?<op>add|adc|and|cmp|or|sub|sbb|xor)\s+(?<args>[^;]+)\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MnemonicUnaryRx = new Regex(
            @"^\s*(?<op>inc|dec)\s+(?<dst>[^;]+)\s*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex PostfixIncDecRx = new Regex(
            @"^\s*(?<dst>[^;]+?)(?<op>\+\+|--)\s*$",
            RegexOptions.Compiled);

        public static Mc1File Parse(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Missing path", nameof(path));
            if (!File.Exists(path)) throw new FileNotFoundException("MC1 file not found", path);
            return ParseLines(File.ReadAllLines(path), path);
        }

        public static Mc1File ParseLines(IReadOnlyList<string> lines, string sourceName = null)
        {
            if (lines == null) throw new ArgumentNullException(nameof(lines));

            var file = new Mc1File { Source = sourceName ?? string.Empty };

            // Built-in type farptr16
            file.Types["farptr16"] = new StructType
            {
                Name = "farptr16",
                Fields = new List<Field> { new Field { Name = "off", Type = "u16" }, new Field { Name = "seg", Type = "u16" } }
            };

            for (var i = 0; i < lines.Count; i++)
            {
                var line = lines[i] ?? string.Empty;
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (CommentLineRx.IsMatch(trimmed)) continue;

                var mType = TypeDeclRx.Match(line);
                if (mType.Success)
                {
                    var name = mType.Groups["name"].Value;
                    var body = mType.Groups["body"].Value;

                    var st = new StructType { Name = name };
                    foreach (Match fm in FieldRx.Matches(body))
                    {
                        st.Fields.Add(new Field { Name = fm.Groups["name"].Value, Type = fm.Groups["type"].Value });
                    }

                    if (st.Fields.Count == 0)
                        throw new InvalidDataException($"Empty struct type '{name}' on line {i + 1}");

                    file.Types[name] = st;
                    continue;
                }

                var mConst = ConstDeclRx.Match(line);
                if (mConst.Success)
                {
                    var name = mConst.Groups["name"].Value;
                    var ty = mConst.Groups["type"].Value.ToLowerInvariant();
                    var valTok = mConst.Groups["val"].Value.Trim();
                    var v = ParseUInt(valTok);
                    file.Consts[name] = new ConstValue { Type = ty, Value = v };
                    continue;
                }

                var mView = ViewDeclRx.Match(line);
                if (mView.Success)
                {
                    var name = mView.Groups["name"].Value;
                    file.Views[name] = new ViewDecl
                    {
                        Name = name,
                        SegExpr = mView.Groups["seg"].Value.Trim(),
                        OffExpr = mView.Groups["off"].Value.Trim(),
                        Type = mView.Groups["type"].Value.Trim(),
                    };
                    continue;
                }

                // Everything else is treated as an MC0 statement line (must keep origin tags if you want verification).
                file.Statements.Add(line);
            }

            return file;
        }

        public static string DesugarToMc0Text(Mc1File mc1)
        {
            if (mc1 == null) throw new ArgumentNullException(nameof(mc1));

            // Apply const substitution to view base expressions deterministically.
            var views = new Dictionary<string, ViewDecl>(StringComparer.Ordinal);
            foreach (var kv in mc1.Views.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                var v = kv.Value;
                views[kv.Key] = new ViewDecl
                {
                    Name = v.Name,
                    Type = v.Type,
                    SegExpr = RewriteConsts(v.SegExpr ?? string.Empty, mc1.Consts),
                    OffExpr = RewriteConsts(v.OffExpr ?? string.Empty, mc1.Consts),
                };
            }

            var sb = new StringBuilder();
            sb.AppendLine("// MC0 desugared from MC1 by DOSRE");
            if (!string.IsNullOrWhiteSpace(mc1.Source)) sb.AppendLine($"// source: {mc1.Source}");
            sb.AppendLine();

            foreach (var raw in mc1.Statements)
            {
                var line = raw ?? string.Empty;
                var rewritten = RewriteConsts(line, mc1.Consts);
                rewritten = RewriteAsmLikeOps(rewritten);
                rewritten = RewritePostfixIncDec(rewritten, views, mc1.Types);
                rewritten = RewriteViewFields(rewritten, views, mc1.Types);
                sb.AppendLine(rewritten);
            }

            return sb.ToString();
        }

        private static string RewriteConsts(string line, Dictionary<string, ConstValue> consts)
        {
            if (consts == null || consts.Count == 0) return line;

            // Replace identifiers with numeric literals (hex) deterministically.
            // Only replace whole-word matches.
            foreach (var kv in consts.OrderBy(k => k.Key, StringComparer.Ordinal))
            {
                var name = kv.Key;
                var v = kv.Value.Value;
                // Use u16-style 0xXXXX when it fits; otherwise 0xXXXXXXXX.
                var lit = v <= 0xFFFF ? $"0x{v:X4}" : $"0x{v:X8}";
                line = Regex.Replace(line, $@"\b{Regex.Escape(name)}\b", lit);
            }

            return line;
        }

        private static string RewriteViewFields(string line, Dictionary<string, ViewDecl> views, Dictionary<string, StructType> types)
        {
            if (views == null || views.Count == 0) return line;

            // Rewrite indexed stores first.
            line = ViewIndexStoreRx.Replace(line, m =>
            {
                var vname = m.Groups["view"].Value;
                var idx = m.Groups["idx"].Value.Trim();
                var rhs = m.Groups["rhs"].Value.Trim();

                if (!views.TryGetValue(vname, out var vd))
                    return m.Value;

                // Indexing is only supported for primitive-typed views.
                var size = SizeOfType(vd.Type, types);
                if (size != 1 && size != 2)
                    return m.Value;

                var offExpr = $"ADD16({vd.OffExpr}, {idx})";
                if (size == 1) return $"STORE8({vd.SegExpr}, {offExpr}, {rhs});";
                return $"STORE16({vd.SegExpr}, {offExpr}, {rhs});";
            });

            // Rewrite stores first so the subsequent LOAD rewrite doesn't turn an lvalue into a LOAD expression.
            line = ViewFieldStoreRx.Replace(line, m =>
            {
                var vname = m.Groups["view"].Value;
                var fname = m.Groups["field"].Value;
                var rhs = m.Groups["rhs"].Value.Trim();

                if (!views.TryGetValue(vname, out var vd))
                    return m.Value;

                if (!types.TryGetValue(vd.Type, out var st))
                    throw new InvalidDataException($"Unknown view type '{vd.Type}' for view '{vname}'");

                var (off, fType) = ResolveFieldOffset(st, fname, types);
                var size = SizeOfType(fType, types);
                var offExpr = $"ADD16({vd.OffExpr}, 0x{off:X4})";

                if (size == 1) return $"STORE8({vd.SegExpr}, {offExpr}, {rhs});";
                if (size == 2) return $"STORE16({vd.SegExpr}, {offExpr}, {rhs});";

                return m.Value;
            });

            // Rewrite indexed loads.
            line = ViewIndexRx.Replace(line, m =>
            {
                var vname = m.Groups["view"].Value;
                var idx = m.Groups["idx"].Value.Trim();

                if (!views.TryGetValue(vname, out var vd))
                    return m.Value;

                var size = SizeOfType(vd.Type, types);
                if (size != 1 && size != 2)
                    return m.Value;

                var offExpr = $"ADD16({vd.OffExpr}, {idx})";
                if (size == 1) return $"LOAD8({vd.SegExpr}, {offExpr})";
                return $"LOAD16({vd.SegExpr}, {offExpr})";
            });

            return ViewFieldRx.Replace(line, m =>
            {
                var vname = m.Groups["view"].Value;
                var fname = m.Groups["field"].Value;

                if (!views.TryGetValue(vname, out var vd))
                    return m.Value;

                if (!types.TryGetValue(vd.Type, out var st))
                    throw new InvalidDataException($"Unknown view type '{vd.Type}' for view '{vname}'");

                var (off, fType) = ResolveFieldOffset(st, fname, types);

                var size = SizeOfType(fType, types);
                // Always use ADD16(base, delta) for a stable normalized form.
                var offExpr = $"ADD16({vd.OffExpr}, 0x{off:X4})";

                // Default rewrite: treat field access as LOADn(seg,off).
                if (size == 1) return $"LOAD8({vd.SegExpr}, {offExpr})";
                if (size == 2) return $"LOAD16({vd.SegExpr}, {offExpr})";

                // Larger fields: leave as-is for now.
                return m.Value;
            });
        }

        private static string RewriteAsmLikeOps(string line)
        {
            // Only rewrite lines that look like origin-tagged statements.
            // (We keep labels and other non-origin lines untouched.)
            var m = Mc0LineRx.Match(line);
            if (!m.Success)
                return line;

            var indent = m.Groups["indent"].Value;
            var stmt = (m.Groups["stmt"].Value ?? string.Empty).Trim();
            var comment = m.Groups["comment"].Value;

            var mu = MnemonicUnaryRx.Match(stmt);
            if (mu.Success)
            {
                var unaryOp = mu.Groups["op"].Value.Trim().ToLowerInvariant();
                var unaryDst = mu.Groups["dst"].Value.Trim();
                var suffix = unaryOp == "inc" ? "++" : "--";
                return $"{indent}{unaryDst}{suffix}; // {comment}";
            }

            var mm = MnemonicBinOpRx.Match(stmt);
            if (!mm.Success)
                return line;

            var op = mm.Groups["op"].Value.Trim().ToUpperInvariant();
            var args = (mm.Groups["args"].Value ?? string.Empty).Trim();
            if (!TrySplitTopLevelComma(args, out var dst, out var src))
                return line;

            dst = dst.Trim();
            src = src.Trim();

            // Normalize "reg" names to their MC0-style uppercase when possible.
            // (Safe: if it's not a reg token, leave as-is.)
            if (dst.Length == 2) dst = dst.ToUpperInvariant();
            if (src.Length == 2) src = src.ToUpperInvariant();

            // CMP is flag-setting and does not write back.
            if (op == "CMP")
                return $"{indent}CMP({dst}, {src}); // {comment}";

            var newStmt = $"{dst} = {op}({dst}, {src})";
            return $"{indent}{newStmt}; // {comment}";
        }

        private static bool TrySplitTopLevelComma(string args, out string left, out string right)
        {
            left = string.Empty;
            right = string.Empty;
            if (string.IsNullOrWhiteSpace(args))
                return false;

            var depthParen = 0;
            var depthBracket = 0;
            for (var i = 0; i < args.Length; i++)
            {
                var ch = args[i];
                switch (ch)
                {
                    case '(':
                        depthParen++;
                        break;
                    case ')':
                        if (depthParen > 0) depthParen--;
                        break;
                    case '[':
                        depthBracket++;
                        break;
                    case ']':
                        if (depthBracket > 0) depthBracket--;
                        break;
                    case ',':
                        if (depthParen == 0 && depthBracket == 0)
                        {
                            left = args.Substring(0, i);
                            right = args.Substring(i + 1);
                            return !string.IsNullOrWhiteSpace(left) && !string.IsNullOrWhiteSpace(right);
                        }

                        break;
                }
            }

            return false;
        }

        private static string RewritePostfixIncDec(string line, Dictionary<string, ViewDecl> views, Dictionary<string, StructType> types)
        {
            var m = Mc0LineRx.Match(line);
            if (!m.Success)
                return line;

            var indent = m.Groups["indent"].Value;
            var stmt = (m.Groups["stmt"].Value ?? string.Empty).Trim();
            var comment = m.Groups["comment"].Value;

            var pm = PostfixIncDecRx.Match(stmt);
            if (!pm.Success)
                return line;

            var dst = pm.Groups["dst"].Value.Trim();
            var op = pm.Groups["op"].Value;

            // Determine width for a nicer immediate literal.
            // - Registers: infer from name.
            // - Views: infer from view type/field type.
            var imm = "0x0001";
            if (TryInferByteWidth(dst, views, types, out var isByte) && isByte)
                imm = "0x01";

            var fn = op == "++" ? "ADD" : "SUB";
            var newStmt = $"{dst} = {fn}({dst}, {imm})";
            return $"{indent}{newStmt}; // {comment}";
        }

        private static bool TryInferByteWidth(string expr, Dictionary<string, ViewDecl> views, Dictionary<string, StructType> types, out bool isByte)
        {
            isByte = false;
            if (string.IsNullOrWhiteSpace(expr))
                return false;

            var e = expr.Trim();

            // Register heuristic.
            if (e.Length == 2)
            {
                var r = e.ToUpperInvariant();
                isByte = r is "AL" or "AH" or "BL" or "BH" or "CL" or "CH" or "DL" or "DH";
                return true;
            }

            // view.field
            var dot = e.IndexOf('.', StringComparison.Ordinal);
            if (dot > 0)
            {
                var vname = e.Substring(0, dot);
                var fname = e.Substring(dot + 1);
                if (views != null && types != null && views.TryGetValue(vname, out var vd) && types.TryGetValue(vd.Type, out var st))
                {
                    var (_, fType) = ResolveFieldOffset(st, fname, types);
                    var size = SizeOfType(fType, types);
                    isByte = size == 1;
                    return true;
                }
            }

            // view[idx]
            var lb = e.IndexOf('[', StringComparison.Ordinal);
            if (lb > 0 && e.EndsWith("]", StringComparison.Ordinal))
            {
                var vname = e.Substring(0, lb);
                if (views != null && types != null && views.TryGetValue(vname, out var vd))
                {
                    var size = SizeOfType(vd.Type, types);
                    isByte = size == 1;
                    return true;
                }
            }

            return false;
        }

        private static (ushort offset, string fieldType) ResolveFieldOffset(StructType st, string field, Dictionary<string, StructType> types)
        {
            ushort off = 0;
            foreach (var f in st.Fields)
            {
                if (string.Equals(f.Name, field, StringComparison.Ordinal))
                    return (off, f.Type);

                var sz = SizeOfType(f.Type, types);
                checked { off = (ushort)(off + sz); }
            }

            throw new InvalidDataException($"Unknown field '{field}' in struct '{st.Name}'");
        }

        private static int SizeOfType(string ty, Dictionary<string, StructType> types)
        {
            switch ((ty ?? string.Empty).ToLowerInvariant())
            {
                case "u8":
                case "bool":
                    return 1;
                case "u16":
                    return 2;
                case "u32":
                    return 4;
            }

            if (types.TryGetValue(ty, out var st))
            {
                var n = 0;
                foreach (var f in st.Fields)
                    n += SizeOfType(f.Type, types);
                return n;
            }

            throw new InvalidDataException($"Unknown type '{ty}'");
        }

        private static uint ParseUInt(string token)
        {
            var s = (token ?? string.Empty).Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);
            if (s.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(0, s.Length - 1);

            if (uint.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
                return hex;

            if (uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
                return dec;

            throw new InvalidDataException($"Bad integer literal '{token}'");
        }
    }
}
