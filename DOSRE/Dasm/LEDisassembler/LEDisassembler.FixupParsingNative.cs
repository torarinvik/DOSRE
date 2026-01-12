using System;
using System.Collections.Generic;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private struct LeFixupRecord
        {
            public byte SourceType;
            public byte TargetFlags;
            public ushort SourceOffset;
            public byte? SourceCount; // If bit 5 of SourceType is set
            public ushort[] SecondarySourceOffsets;

            public ushort? SkipCount; // If bit 7 of TargetFlags is set

            public byte TargetType => (byte)(TargetFlags & 0x03);
            public ushort TargetObject;
            public uint TargetOffset;
            public int RecordLength;
            public int RecordStreamOffset;
        }

        private static LeFixupRecord? DecipherFixupRecord(byte[] data, int start, int end)
        {
            if (data == null || start < 0 || start + 4 > end) return null;
            var rec = new LeFixupRecord();
            rec.RecordStreamOffset = start;
            rec.SourceType = data[start + 0];
            rec.TargetFlags = data[start + 1];
            rec.SourceOffset = (ushort)(data[start + 2] | (data[start + 3] << 8));
            var p = start + 4;

            // Bit 5 of SourceType: List of source offsets follows
            if ((rec.SourceType & 0x20) != 0)
            {
                if (p + 1 > end) return null;
                rec.SourceCount = data[p++];
            }

            // Bit 7 of TargetFlags: Skip field present
            if ((rec.TargetFlags & 0x80) != 0)
            {
                if (p + 2 > end) return null;
                rec.SkipCount = (ushort)(data[p] | (data[p + 1] << 8));
                p += 2;
            }

            int objSize = (rec.TargetFlags & 0x10) != 0 ? 2 : 1;
            int offSize = 0;
            if ((rec.TargetFlags & 0x40) != 0) offSize = 1;
            else if ((rec.TargetFlags & 0x20) != 0) offSize = 4;
            else offSize = 2;

            var targetType = rec.TargetType;
            // Ordinal target? (1 or 2)
            if (targetType == 1 || targetType == 2) {
                // For imports, bit 4 means 16-bit module ordinal, else 8-bit.
                // TargetOffset is Procedure Ordinal (if type 1) or Name Offset (if type 2).
                // Procedure Ordinal size: Bit 6=1 -> 8-bit, Bit 5=1 -> 32-bit, else 16-bit.
                // But wait, many specs say procedure ordinal is always 16-bit for type 1?
                // Let's stick to our offSize logic for now.
            }

            if (p + objSize > end) return null;
            if (objSize == 1) rec.TargetObject = data[p++];
            else { rec.TargetObject = (ushort)(data[p] | (data[p + 1] << 8)); p += 2; }

            if (p + offSize > end) return null;
            if (offSize == 1) rec.TargetOffset = data[p++];
            else if (offSize == 2) { rec.TargetOffset = (ushort)(data[p] | (data[p + 1] << 8)); p += 2; }
            else { rec.TargetOffset = ReadUInt32(data, p); p += 4; }

            if (rec.SourceCount > 1)
            {
                var count = rec.SourceCount.Value;
                rec.SecondarySourceOffsets = new ushort[count - 1];
                for (int i = 0; i < count - 1; i++) {
                    if (p + 2 > end) break;
                    rec.SecondarySourceOffsets[i] = (ushort)(data[p] | (data[p + 1] << 8));
                    p += 2;
                }
            }

            rec.RecordLength = p - start;
            return rec;
        }

        private static List<LeFixupRecord> ParseAllRecordsForPage(byte[] stream, int start, int end)
        {
            var results = new List<LeFixupRecord>();
            var p = start;
            while (p < end) {
                var rec = DecipherFixupRecord(stream, p, end);
                if (rec == null || rec.Value.RecordLength <= 0) break;
                results.Add(rec.Value);
                p += rec.Value.RecordLength;
                if (results.Count > 5000) break;
            }
            return results;
        }
    }
}
