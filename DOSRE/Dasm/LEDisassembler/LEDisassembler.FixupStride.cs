using System;
using System.Text;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private readonly struct StrideGuess
        {
            public int Stride { get; }
            public double Score { get; }
            public int ValidSrcOff { get; }
            public int EntriesChecked { get; }

            public StrideGuess(int stride, double score, int validSrcOff, int entriesChecked)
            {
                Stride = stride;
                Score = score;
                ValidSrcOff = validSrcOff;
                EntriesChecked = entriesChecked;
            }
        }

        private static StrideGuess GuessStride(byte[] data, int start, int len, int pageSize)
        {
            // DOS4GW fixup record streams often appear to be fixed-stride within a page.
            // We'll score likely strides based on whether the 16-bit source offset field looks plausible.
            var candidates = new[] { 8, 10, 12, 16 };
            var best = new StrideGuess(16, double.NegativeInfinity, 0, 0);

            foreach (var stride in candidates)
            {
                if (stride <= 0 || len < stride)
                    continue;

                var entries = Math.Min(len / stride, 128);
                var checkedEntries = 0;
                var validSrcOff = 0;
                double score = 0;

                for (var i = 0; i < entries; i++)
                {
                    var off = start + i * stride;
                    if (off + 4 > start + len)
                        break;

                    var srcType = data[off + 0];
                    var flags = data[off + 1];
                    var srcOff = (ushort)(data[off + 2] | (data[off + 3] << 8));
                    if (srcOff >= pageSize)
                    {
                        var swapped = (ushort)((srcOff >> 8) | (srcOff << 8));
                        if (swapped < pageSize)
                            srcOff = swapped;
                    }

                    checkedEntries++;

                    // Source offset should generally be within the page.
                    if (srcOff < pageSize)
                    {
                        validSrcOff++;
                        score += 2.0;
                    }
                    else
                    {
                        score -= 2.0;
                    }

                    // Mild preference for non-trivial values (avoid matching on all-zeros garbage).
                    if (srcType != 0x00 && srcType != 0xFF)
                        score += 0.25;
                    if (flags != 0x00 && flags != 0xFF)
                        score += 0.10;
                }

                if (len % stride == 0)
                    score += 5.0;

                // Prefer higher valid ratio.
                if (checkedEntries > 0)
                    score += 5.0 * ((double)validSrcOff / checkedEntries);

                if (score > best.Score)
                    best = new StrideGuess(stride, score, validSrcOff, checkedEntries);
            }

            // Fallback
            if (double.IsNegativeInfinity(best.Score))
                return new StrideGuess(16, 0, 0, 0);

            return best;
        }

        private static string DumpStrideView(byte[] data, int start, int end, int stride, int maxEntries)
        {
            if (data == null || stride <= 0 || start < 0 || end > data.Length || end <= start)
                return string.Empty;

            var sb = new StringBuilder();
            var len = end - start;
            var entries = Math.Min(len / stride, maxEntries);

            for (var i = 0; i < entries; i++)
            {
                var off = start + i * stride;
                if (off + stride > end)
                    break;

                var srcType = data[off + 0];
                var flags = data[off + 1];
                var srcOff = (ushort)(data[off + 2] | (data[off + 3] << 8));
                var restLen = Math.Max(0, stride - 4);
                var rest = restLen == 0 ? string.Empty : BitConverter.ToString(data, off + 4, restLen).Replace("-", " ");

                sb.AppendLine($";   [{i:00}] +0x{(off - start):X3}  type=0x{srcType:X2} flags=0x{flags:X2} srcOff=0x{srcOff:X4}  rest={rest}");
            }

            return sb.ToString().TrimEnd();
        }
    }
}
