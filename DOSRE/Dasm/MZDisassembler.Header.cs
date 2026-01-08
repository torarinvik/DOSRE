using System;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
        private sealed class MZHeader
        {
            public ushort e_magic;
            public ushort e_cblp;
            public ushort e_cp;
            public ushort e_crlc;
            public ushort e_cparhdr;
            public ushort e_minalloc;
            public ushort e_maxalloc;
            public ushort e_ss;
            public ushort e_sp;
            public ushort e_csum;
            public ushort e_ip;
            public ushort e_cs;
            public ushort e_lfarlc;
            public ushort e_ovno;
            public uint e_lfanew;
        }

        private static bool TryParseMZHeader(byte[] fileBytes, out MZHeader h)
        {
            h = null;
            if (fileBytes == null || fileBytes.Length < 64)
                return false;
            if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
                return false;

            h = new MZHeader
            {
                e_magic = ReadUInt16(fileBytes, 0x00),
                e_cblp = ReadUInt16(fileBytes, 0x02),
                e_cp = ReadUInt16(fileBytes, 0x04),
                e_crlc = ReadUInt16(fileBytes, 0x06),
                e_cparhdr = ReadUInt16(fileBytes, 0x08),
                e_minalloc = ReadUInt16(fileBytes, 0x0A),
                e_maxalloc = ReadUInt16(fileBytes, 0x0C),
                e_ss = ReadUInt16(fileBytes, 0x0E),
                e_sp = ReadUInt16(fileBytes, 0x10),
                e_csum = ReadUInt16(fileBytes, 0x12),
                e_ip = ReadUInt16(fileBytes, 0x14),
                e_cs = ReadUInt16(fileBytes, 0x16),
                e_lfarlc = ReadUInt16(fileBytes, 0x18),
                e_ovno = ReadUInt16(fileBytes, 0x1A),
                e_lfanew = fileBytes.Length >= 0x40 ? ReadUInt32(fileBytes, 0x3C) : 0
            };

            return true;
        }

        private static int ComputeMzFileSizeBytes(MZHeader h, int fallbackLen)
        {
            if (h == null)
                return fallbackLen;
            if (h.e_cp == 0)
                return fallbackLen;

            var size = (h.e_cp - 1) * 512;
            if (h.e_cblp == 0)
                size += 512;
            else
                size += h.e_cblp;
            return (int)size;
        }
    }
}
