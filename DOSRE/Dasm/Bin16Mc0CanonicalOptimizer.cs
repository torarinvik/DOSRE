using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm;

public static class Bin16Mc0CanonicalOptimizer
{
    private static readonly Regex IfJccGotoRx = new Regex(
        @"^\s*if\s*\(\s*(?<cond>[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\)\s*goto\s+(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex GotoRx = new Regex(
        @"^\s*(?:else\s+)?goto\s+(?<lbl>[A-Za-z_.$@?][A-Za-z0-9_.$@?]*)\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex LocLabelAddrRx = new Regex(
        @"^loc_(?<addr>[0-9A-Fa-f]{4,8})$",
        RegexOptions.Compiled);

    // Cond function name -> short Jcc opcode
    // (Only the short 0x70..0x7F family. JCXZ is excluded.)
    private static readonly Dictionary<string, byte> CondToOpcode = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JO"] = 0x70,
        ["JNO"] = 0x71,
        ["JB"] = 0x72,
        ["JNAE"] = 0x72,
        ["JNB"] = 0x73,
        ["JAE"] = 0x73,
        ["JZ"] = 0x74,
        ["JE"] = 0x74,
        ["JNZ"] = 0x75,
        ["JNE"] = 0x75,
        ["JBE"] = 0x76,
        ["JNA"] = 0x76,
        ["JA"] = 0x77,
        ["JNBE"] = 0x77,
        ["JS"] = 0x78,
        ["JNS"] = 0x79,
        ["JP"] = 0x7A,
        ["JPE"] = 0x7A,
        ["JNP"] = 0x7B,
        ["JPO"] = 0x7B,
        ["JL"] = 0x7C,
        ["JNGE"] = 0x7C,
        ["JGE"] = 0x7D,
        ["JNL"] = 0x7D,
        ["JLE"] = 0x7E,
        ["JNG"] = 0x7E,
        ["JG"] = 0x7F,
        ["JNLE"] = 0x7F,
    };

    private static readonly Dictionary<string, string> InvertCond = new(StringComparer.OrdinalIgnoreCase)
    {
        ["JO"] = "JNO",
        ["JNO"] = "JO",
        ["JB"] = "JAE",
        ["JNAE"] = "JAE",
        ["JAE"] = "JB",
        ["JNB"] = "JB",
        ["JZ"] = "JNZ",
        ["JE"] = "JNZ",
        ["JNZ"] = "JZ",
        ["JNE"] = "JZ",
        ["JBE"] = "JA",
        ["JNA"] = "JA",
        ["JA"] = "JBE",
        ["JNBE"] = "JBE",
        ["JS"] = "JNS",
        ["JNS"] = "JS",
        ["JP"] = "JNP",
        ["JPE"] = "JNP",
        ["JNP"] = "JP",
        ["JPO"] = "JP",
        ["JL"] = "JGE",
        ["JNGE"] = "JGE",
        ["JGE"] = "JL",
        ["JNL"] = "JL",
        ["JLE"] = "JG",
        ["JNG"] = "JG",
        ["JG"] = "JLE",
        ["JNLE"] = "JLE",
    };

    public sealed record OptimizeResult(int Candidates, int Applied, int Skipped);

    /// <summary>
    /// Canonical optimization that is mechanically provable and length-preserving:
    ///
    /// If the stream contains:
    ///   A:  if (Jcc()) goto THEN;    (short Jcc)
    ///   A+2: goto ELSE;             (short/near JMP)
    /// and THEN is exactly the fallthrough address after the JMP,
    /// and ELSE is within short range from A+2,
    /// rewrite to:
    ///   A:  if (J!cc()) goto ELSE;  (short Jcc)
    ///   A+2: NOP...                 (same length as original JMP)
    ///
    /// This removes the unconditional branch while preserving statement byte lengths.
    ///
    /// NOTE: This mutates <paramref name="mc0"/>.
    /// </summary>
    public static OptimizeResult OptimizeInvertJccSkipJmp(Bin16Mc0.Mc0File mc0)
    {
        if (mc0 == null) throw new ArgumentNullException(nameof(mc0));

        var labelToAddr = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);
        foreach (var st in mc0.Statements)
        {
            if (st.Labels == null) continue;
            foreach (var lbl in st.Labels)
            {
                if (string.IsNullOrWhiteSpace(lbl)) continue;
                if (!labelToAddr.ContainsKey(lbl))
                    labelToAddr[lbl] = st.Addr;
            }
        }

        var candidates = 0;
        var applied = 0;
        var skipped = 0;

        for (var i = 0; i + 1 < mc0.Statements.Count; i++)
        {
            var a = mc0.Statements[i];
            var b = mc0.Statements[i + 1];

            var ifm = IfJccGotoRx.Match(a.Mc0 ?? string.Empty);
            if (!ifm.Success) continue;

            if ((a.BytesHex?.Length ?? 0) != 4) continue; // short Jcc must be 2 bytes

            candidates++;

            if (!TryParseHexByte(a.BytesHex.AsSpan(0, 2), out var aOp)) { skipped++; continue; }
            if (aOp < 0x70 || aOp > 0x7F) { skipped++; continue; }

            var cond = ifm.Groups["cond"].Value;
            if (!CondToOpcode.TryGetValue(cond, out var expectedOp) || expectedOp != aOp)
            {
                skipped++;
                continue;
            }

            if (!InvertCond.TryGetValue(cond, out var invCond)) { skipped++; continue; }
            var invOp = (byte)(aOp ^ 0x01);
            if (!CondToOpcode.TryGetValue(invCond, out var invExpected) || invExpected != invOp)
            {
                skipped++;
                continue;
            }

            var thenLbl = ifm.Groups["lbl"].Value;
            if (!TryResolveLabelAddr(labelToAddr, thenLbl, out var thenAddr)) { skipped++; continue; }

            var gotom = GotoRx.Match(b.Mc0 ?? string.Empty);
            if (!gotom.Success) { skipped++; continue; }

            var elseLbl = gotom.Groups["lbl"].Value;
            if (!TryResolveLabelAddr(labelToAddr, elseLbl, out var elseAddr)) { skipped++; continue; }

            var lenA = (uint)(a.BytesHex.Length / 2);
            var lenB = (uint)((b.BytesHex?.Length ?? 0) / 2);
            if (lenB == 0) { skipped++; continue; }

            // Require exact adjacency for the classic pattern.
            if (b.Addr != a.Addr + lenA) { skipped++; continue; }

            // THEN must be the fallthrough after the unconditional goto.
            var fallthroughAfterB = b.Addr + lenB;
            if (thenAddr != fallthroughAfterB) { skipped++; continue; }

            // Ensure B is actually a JMP encoding (short or near) so replacing with NOP is valid.
            if (!TryParseHexByte(b.BytesHex.AsSpan(0, 2), out var bOp)) { skipped++; continue; }
            if (bOp != 0xE9 && bOp != 0xEB)
            {
                skipped++;
                continue;
            }

            // Ensure ELSE fits in short Jcc range from the next instruction (A+2).
            var relBase = (int)(a.Addr + lenA);
            var rel = (int)elseAddr - relBase;
            if (rel < sbyte.MinValue || rel > sbyte.MaxValue)
            {
                skipped++;
                continue;
            }

            // Apply rewrite:
            // A: opcode becomes inverted; displacement updated to ELSE
            var disp = unchecked((byte)(sbyte)rel);
            a.BytesHex = $"{invOp:X2}{disp:X2}";
            a.Mc0 = $"if ({invCond}()) goto {elseLbl}";

            // B: become NOPs of same length
            var sbNop = new StringBuilder((int)lenB * 2);
            for (var k = 0; k < lenB; k++) sbNop.Append("90");
            var nopHex = sbNop.ToString();

            b.BytesHex = nopHex;
            b.Mc0 = $"EMITHEX(\"{nopHex.ToLowerInvariant()}\")";

            applied++;
            i++; // skip over rewritten B
        }

        return new OptimizeResult(candidates, applied, skipped);
    }

    private static bool TryResolveLabelAddr(IReadOnlyDictionary<string, uint> known, string label, out uint addr)
    {
        addr = 0;
        if (string.IsNullOrWhiteSpace(label)) return false;
        if (known != null && known.TryGetValue(label, out addr)) return true;

        var m = LocLabelAddrRx.Match(label.Trim());
        if (!m.Success) return false;
        var hex = m.Groups["addr"].Value;
        return uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out addr);
    }

    private static bool TryParseHexByte(ReadOnlySpan<char> hex2, out byte b)
    {
        b = 0;
        if (hex2.Length != 2) return false;
        return byte.TryParse(hex2, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b);
    }
}
