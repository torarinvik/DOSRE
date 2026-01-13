using System;
using System.Collections.Generic;
using System.Text;
using SharpDisasm;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private static void ScanStrings(List<LEObject> objects, Dictionary<int, byte[]> objBytesByIndex, out Dictionary<uint, string> symbols, out Dictionary<uint, string> preview)
        {
            symbols = new Dictionary<uint, string>();
            preview = new Dictionary<uint, string>();

            if (objects == null || objBytesByIndex == null)
                return;

            // Very lightweight string scan: runs of printable bytes terminated by 0.
            // To reduce noise, prefer scanning non-executable objects (data-ish) first.
            // Some binaries embed useful strings inside CODE objects; if we find none in data,
            // do a conservative fallback scan over executable objects as well.

            static void ScanObjectBytes(LEObject obj, byte[] bytes, Dictionary<uint, string> syms, Dictionary<uint, string> prev)
            {
                if (bytes == null || bytes.Length == 0)
                    return;

                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)bytes.Length);
                var i = 0;
                while (i < maxLen)
                {
                    // Find start of a printable run.
                    if (!IsLikelyStringChar(bytes[i]))
                    {
                        i++;
                        continue;
                    }

                    var start = i;
                    var sb = new StringBuilder();
                    while (i < maxLen && IsLikelyStringChar(bytes[i]) && sb.Length < 200)
                    {
                        sb.Append((char)bytes[i]);
                        i++;
                    }

                    // Require NUL terminator nearby to avoid random data.
                    var nul = (i < maxLen && bytes[i] == 0x00);
                    var s = sb.ToString();
                    if (nul && s.Length >= 4 && LooksLikeHumanString(s))
                    {
                        var linear = obj.BaseAddress + (uint)start;
                        if (!syms.ContainsKey(linear))
                        {
                            syms[linear] = $"s_{linear:X8}";
                            prev[linear] = EscapeForComment(s);
                        }
                    }

                    // Skip the terminator if present.
                    if (nul)
                        i++;
                }
            }

            foreach (var obj in objects)
            {
                var isExecutable = (obj.Flags & 0x0004) != 0;
                if (isExecutable)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes))
                    continue;

                ScanObjectBytes(obj, bytes, symbols, preview);
            }

            if (symbols.Count == 0)
            {
                foreach (var obj in objects)
                {
                    var isExecutable = (obj.Flags & 0x0004) != 0;
                    if (!isExecutable)
                        continue;

                    if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes))
                        continue;

                    ScanObjectBytes(obj, bytes, symbols, preview);
                }
            }
        }

        private static bool LooksLikeHumanString(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4)
                return false;

            var letters = 0;
            var digits = 0;
            var spaces = 0;
            var punctuation = 0;

            foreach (var ch in s)
            {
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
                    letters++;
                else if (ch >= '0' && ch <= '9')
                    digits++;
                else if (ch == ' ')
                    spaces++;
                else if (".,:;!?/\\-_()[]{}'\"".IndexOf(ch) >= 0)
                    punctuation++;
            }

            // Require at least some real “text signal”.
            if (letters < 2)
                return false;

            // Avoid things that are almost all hex-ish or symbols.
            if (letters + digits + spaces + punctuation == 0)
                return false;

            // Prefer either spaces or common punctuation or longer strings.
            return spaces > 0 || punctuation > 0 || s.Length >= 10;
        }

        private static bool IsLikelyStringChar(byte b)
        {
            // Accept basic printable ASCII plus a few common CP437 punctuation bytes.
            if (b >= 0x20 && b <= 0x7E)
                return true;
            // Tab
            if (b == 0x09)
                return true;
            return false;
        }

        private static string EscapeForComment(string s)
        {
            if (string.IsNullOrEmpty(s))
                return string.Empty;

            // Keep comments readable
            s = s.Replace("\\r", " ").Replace("\\n", " ").Replace("\t", " ");
            if (s.Length > 120)
                s = s.Substring(0, 120) + "...";
            return s;
        }

        private static string ApplyStringSymbolRewrites(Instruction ins, string insText, List<LEFixup> fixupsHere, Dictionary<uint, string> stringSymbols, List<LEObject> objects = null)
        {
            if (stringSymbols == null || stringSymbols.Count == 0 || fixupsHere == null || fixupsHere.Count == 0)
                return insText;

            var rewritten = insText;
            foreach (var f in fixupsHere)
            {
                if (!TryGetFixupFieldStartDelta32(ins, f, out var delta, out var kind))
                    continue;

                // Strings typically appear as imm32 addresses (push/mov) but can be disp32 too.
                if (kind != "imm32" && kind != "imm32?" && kind != "disp32")
                    continue;

                var raw = BitConverter.ToUInt32(ins.Bytes, delta);
                string sym = null;

                // Common case: raw already equals a linear string address.
                if (!stringSymbols.TryGetValue(raw, out sym))
                {
                    // Common DOS4GW pattern: raw is a small offset into a fixed resource region or any object.
                    // If base+raw matches a known string symbol, rewrite the raw immediate to that symbol.
                    if (raw >= 0x10 && raw < 0x20000 && objects != null)
                    {
                        foreach (var obj in objects)
                        {
                            var linear = unchecked(obj.BaseAddress + raw);
                            if (stringSymbols.TryGetValue(linear, out sym))
                                break;
                        }
                    }

                    if (string.IsNullOrEmpty(sym))
                    {
                        // Fallback: check hardcoded typical bases if objects list is somehow insufficient.
                        foreach (var baseAddr in new[] { 0x000C0000u, 0x000D0000u, 0x000E0000u, 0x000F0000u })
                        {
                            var linear = unchecked(baseAddr + raw);
                            if (stringSymbols.TryGetValue(linear, out sym))
                                break;
                        }
                    }

                    // Fallback: sometimes raw is object-relative and the fixup mapping tells us the true target.
                    if (objects != null && f.TargetObject.HasValue && f.TargetOffset.HasValue)
                    {
                        var objIndex = f.TargetObject.Value;
                        if (objIndex >= 1 && objIndex <= objects.Count)
                        {
                            var linear = unchecked(objects[objIndex - 1].BaseAddress + f.TargetOffset.Value);
                            stringSymbols.TryGetValue(linear, out sym);
                        }
                    }
                }

                if (string.IsNullOrEmpty(sym))
                    continue;

                var needleLower = $"0x{raw:x}";
                var needleUpper = $"0x{raw:X}";
                rewritten = rewritten.Replace(needleLower, sym).Replace(needleUpper, sym);
            }

            return rewritten;
        }
    }
}
