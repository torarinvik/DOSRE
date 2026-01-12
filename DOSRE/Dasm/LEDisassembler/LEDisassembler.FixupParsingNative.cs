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

        private static LeFixupRecord? DecipherFixupRecord(byte[] data, int start, int end, bool assumeLX)
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

            int objSize = 1;
            int offSize = 2;

            // Heuristic for LE variants:
            // Standard LX: Bit 4=16-bit Obj, Bit 5=32-bit Off.
            // Some Watcom/DOS4GW LEs: Bit 4=32-bit Off, Bit 5=16-bit Obj.
            // We use the presence of Bit 5 in a small-object binary to guess it's LX, 
            // but if we see Bit 4 and it results in a huge object number, we pivot.
            
            bool isLX = assumeLX; 
            if (!assumeLX && (rec.TargetFlags & 0x10) != 0) {
                // If Bit 4 is set, check the next byte. If it's 0 (most objects are < 256),
                // it's ambiguous. But if we assume bit 4 is 32-bit offset, offSize=4, objSize=1.
                // Let's try to detect based on record length or other clues.
                // For now, let's look at the actual byte at p+1 if objSize=2.
                if (p + 2 <= end && data[p+1] != 0 && data[p+1] != 0xFF) {
                    // If the high byte of a 16-bit object is non-zero, it's likely actually an offset byte.
                    isLX = false;
                }
            }

            if (isLX) {
                objSize = (rec.TargetFlags & 0x10) != 0 ? 2 : 1;
                if ((rec.TargetFlags & 0x40) != 0) offSize = 1;
                else if ((rec.TargetFlags & 0x20) != 0) offSize = 4;
                else offSize = 2;
            } else {
                objSize = (rec.TargetFlags & 0x20) != 0 ? 2 : 1;
                if ((rec.TargetFlags & 0x40) != 0) offSize = 1;
                else if ((rec.TargetFlags & 0x10) != 0) offSize = 4;
                else offSize = 2;
            }

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
            else { rec.TargetOffset = ReadLEUInt32(data, p); p += 4; }

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

        private static List<LeFixupRecord> ParseAllRecordsForPage(byte[] stream, int start, int end, bool assumeLX)
        {
            var results = new List<LeFixupRecord>();
            var p = start;
            while (p < end) {
                var rec = DecipherFixupRecord(stream, p, end, assumeLX);
                if (rec == null || rec.Value.RecordLength <= 0) break;
                results.Add(rec.Value);
                p += rec.Value.RecordLength;
                if (results.Count > 5000) break;
            }
            return results;
        }
    }
}
