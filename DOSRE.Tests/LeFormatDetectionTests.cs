using System.Reflection;
using System.Linq;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeFormatDetectionTests
    {
        private static (bool ok, int offset) InvokeTryFindLeHeaderOffsetDefault(byte[] bytes)
        {
            var m = typeof(LEDisassembler).GetMethod(
                "TryFindLEHeaderOffset",
                BindingFlags.NonPublic | BindingFlags.Static,
                binder: null,
                types: new[] { typeof(byte[]), typeof(int).MakeByRefType() },
                modifiers: null);

            Assert.NotNull(m);

            object[] args = { bytes, 0 };
            var ok = (bool)m!.Invoke(null, args)!;
            var off = (int)args[1];
            return (ok, off);
        }

        private static (bool ok, int offset) InvokeTryFindLeHeaderOffset(byte[] bytes, bool allowMzOverlayScanFallback)
        {
            var m = typeof(LEDisassembler)
                .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
                .FirstOrDefault(mi =>
                {
                    if (mi.Name != "TryFindLEHeaderOffset")
                        return false;

                    var ps = mi.GetParameters();
                    if (ps.Length != 3)
                        return false;

                    return ps[0].ParameterType == typeof(byte[]) &&
                           ps[1].ParameterType == typeof(bool) &&
                           ps[2].ParameterType.IsByRef &&
                           ps[2].ParameterType.GetElementType() == typeof(int);
                });

            Assert.NotNull(m);

            object[] args = { bytes, allowMzOverlayScanFallback, 0 };
            var ok = (bool)m!.Invoke(null, args)!;
            var off = (int)args[2];
            return (ok, off);
        }

        [Fact]
        public void TryFindLEHeaderOffset_FindsEmbeddedBoundMZLEBehindBwOverlay()
        {
            // Synthetic layout:
            //   0x0000: Outer MZ header (e_cp=1, e_cblp=0x100) => overlayBase=0x100
            //   0x0100: "BW" + headerLen + u32 field containing rel pointer to inner MZ
            //   0x0200: Inner MZ header with e_lfanew=0x80
            //   0x0280: LE header ("LE\0\0") with minimal required fields for TryParseHeader()
            var bytes = new byte[0x400];

            // Outer MZ signature.
            bytes[0x00] = (byte)'M';
            bytes[0x01] = (byte)'Z';
            // e_cblp (bytes in last page) = 0x0100
            bytes[0x02] = 0x00;
            bytes[0x03] = 0x01;
            // e_cp (pages in file) = 1
            bytes[0x04] = 0x01;
            bytes[0x05] = 0x00;
            // e_lfanew = 0 (forces BW overlay path)
            bytes[0x3C] = 0x00;
            bytes[0x3D] = 0x00;
            bytes[0x3E] = 0x00;
            bytes[0x3F] = 0x00;

            // BW header at overlay base 0x100.
            bytes[0x100] = (byte)'B';
            bytes[0x101] = (byte)'W';
            // bwHeaderLen = 0x20
            bytes[0x102] = 0x20;
            bytes[0x103] = 0x00;
            // u32 rel pointer at fieldOff=4 => inner MZ at 0x200 (rel=0x100).
            bytes[0x104] = 0x00;
            bytes[0x105] = 0x01;
            bytes[0x106] = 0x00;
            bytes[0x107] = 0x00;

            // Inner MZ at 0x200.
            bytes[0x200] = (byte)'M';
            bytes[0x201] = (byte)'Z';
            // inner e_lfanew = 0x80
            bytes[0x23C] = 0x80;
            bytes[0x23D] = 0x00;
            bytes[0x23E] = 0x00;
            bytes[0x23F] = 0x00;

            // LE header at 0x280: "LE\0\0"
            bytes[0x280] = (byte)'L';
            bytes[0x281] = (byte)'E';
            bytes[0x282] = 0x00;
            bytes[0x283] = 0x00;
            // word order at +0x04 (must be 0)
            bytes[0x284] = 0x00;
            bytes[0x285] = 0x00;
            // NumberOfPages at +0x14 = 1
            bytes[0x294] = 0x01;
            bytes[0x295] = 0x00;
            bytes[0x296] = 0x00;
            bytes[0x297] = 0x00;
            // ObjectCount at +0x44 = 1
            bytes[0x2C4] = 0x01;
            bytes[0x2C5] = 0x00;
            bytes[0x2C6] = 0x00;
            bytes[0x2C7] = 0x00;
            // PageSize at +0x28 = 0x1000
            bytes[0x2A8] = 0x00;
            bytes[0x2A9] = 0x10;
            bytes[0x2AA] = 0x00;
            bytes[0x2AB] = 0x00;

            var (ok, off) = InvokeTryFindLeHeaderOffsetDefault(bytes);
            Assert.True(ok);
            Assert.Equal(0x280, off);
        }

        [Fact]
        public void TryFindLEHeaderOffset_MzOverlayScanFallback_FindsLeInOverlay_WhenEnabled()
        {
            // Synthetic layout:
            //   0x0000: Outer MZ header (e_cp=1, e_cblp=0x200) => overlayBase=0x200
            //   0x0240: LE header (valid)
            // No BW header and e_lfanew=0 => default path should fail unless scan fallback is enabled.
            var bytes = new byte[0x600];

            bytes[0x00] = (byte)'M';
            bytes[0x01] = (byte)'Z';

            // e_cblp = 0x0200
            bytes[0x02] = 0x00;
            bytes[0x03] = 0x02;
            // e_cp = 1
            bytes[0x04] = 0x01;
            bytes[0x05] = 0x00;
            // e_lfanew = 0 (forces fallback path; no BW header present)
            bytes[0x3C] = 0x00;
            bytes[0x3D] = 0x00;
            bytes[0x3E] = 0x00;
            bytes[0x3F] = 0x00;

            // Valid LE header at 0x240
            var leOff = 0x240;
            bytes[leOff + 0x00] = (byte)'L';
            bytes[leOff + 0x01] = (byte)'E';
            bytes[leOff + 0x02] = 0x00;
            bytes[leOff + 0x03] = 0x00;

            // NumberOfPages at +0x14 = 1
            bytes[leOff + 0x14] = 0x01;
            // PageSize at +0x28 = 0x1000
            bytes[leOff + 0x28] = 0x00;
            bytes[leOff + 0x29] = 0x10;
            // ObjectCount at +0x44 = 1
            bytes[leOff + 0x44] = 0x01;

            // Default behavior (no scan): should fail.
            var (okDefault, _) = InvokeTryFindLeHeaderOffsetDefault(bytes);
            Assert.False(okDefault);

            // Opt-in scan: should succeed.
            var (ok, off) = InvokeTryFindLeHeaderOffset(bytes, allowMzOverlayScanFallback: true);
            Assert.True(ok);
            Assert.Equal(leOff, off);
        }

        [Fact]
        public void TryFindLEHeaderOffset_MzOverlayScanFallback_DoesNotAcceptInvalidLeSignature()
        {
            // Same as above, but with an LE\0\0 signature and invalid header fields.
            var bytes = new byte[0x600];

            bytes[0x00] = (byte)'M';
            bytes[0x01] = (byte)'Z';

            // overlayBase = 0x200
            bytes[0x02] = 0x00;
            bytes[0x03] = 0x02;
            bytes[0x04] = 0x01;
            bytes[0x05] = 0x00;

            // e_lfanew = 0
            bytes[0x3C] = 0x00;
            bytes[0x3D] = 0x00;
            bytes[0x3E] = 0x00;
            bytes[0x3F] = 0x00;

            var leOff = 0x240;
            bytes[leOff + 0x00] = (byte)'L';
            bytes[leOff + 0x01] = (byte)'E';
            bytes[leOff + 0x02] = 0x00;
            bytes[leOff + 0x03] = 0x00;

            // Leave NumberOfPages/ObjectCount/PageSize as zero => TryParseHeader must reject.
            var (ok, off) = InvokeTryFindLeHeaderOffset(bytes, allowMzOverlayScanFallback: true);
            Assert.False(ok);
            Assert.Equal(0, off);
        }
    }
}

