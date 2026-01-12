using System;
using System.Collections.Generic;
using System.Text;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private const ushort LE_OBJECT_ENTRY_SIZE = 24;

        private static ulong ComputeEntryLinear(LEHeader header, List<LEObject> objects)
        {
            if (header.EntryEipObject == 0)
                return 0;

            var obj = objects.Find(o => o.Index == header.EntryEipObject);
            return obj.BaseAddress + header.EntryEip;
        }

        private static bool TryFindLEHeaderOffset(byte[] fileBytes, out int offset)
        {
            return TryFindLEHeaderOffset(fileBytes, allowMzOverlayScanFallback: false, out offset);
        }

        private static bool TryFindLEHeaderOffset(byte[] fileBytes, bool allowMzOverlayScanFallback, out int offset)
        {
            offset = 0;
            if (fileBytes == null || fileBytes.Length < 0x40)
                return false;

            // First: if this is an MZ container, prefer e_lfanew.
            // This avoids false positives where an "LE\0\0" byte sequence appears in the stub or data.
            var isMz = fileBytes[0] == (byte)'M' && fileBytes[1] == (byte)'Z';
            if (isMz)
            {
                var lfanew = (int)ReadUInt32(fileBytes, 0x3C);
                var lfanewLooksInvalid = lfanew <= 0 || lfanew + 4 > fileBytes.Length;
                if (!lfanewLooksInvalid)
                {
                    if (fileBytes[lfanew] == (byte)'L' && fileBytes[lfanew + 1] == (byte)'E' && fileBytes[lfanew + 2] == 0x00 &&
                        fileBytes[lfanew + 3] == 0x00)
                    {
                        if (TryParseHeader(fileBytes, lfanew, out var _, out var _))
                        {
                            offset = lfanew;
                            return true;
                        }
                    }
                }

                // Next: handle BW overlay containers (EURO96/EUROBLST-style), where the *real* bound MZ+LE lives
                // behind a BW overlay header and e_lfanew may be bogus/out-of-range.
                if (TryFindEmbeddedLeOffsetFromBwOverlay(fileBytes, out var bwLeOffset) &&
                    TryParseHeader(fileBytes, bwLeOffset, out var _, out var _))
                {
                    offset = bwLeOffset;
                    return true;
                }

                // Constrained fallback scan *only* in the overlay region.
                // - If explicitly enabled, always try.
                // - If e_lfanew is clearly bogus/out-of-range, try automatically (real-world DOS4GW stubs exist like this).
                if ((allowMzOverlayScanFallback || lfanewLooksInvalid) &&
                    TryScanForLeHeaderInMzOverlay(fileBytes, out var scanOffset))
                {
                    offset = scanOffset;
                    return true;
                }

                // Default behavior: do NOT scan inside MZ containers.
                offset = 0;
                return false;
            }

            // Fallback: scan for a plausible LE signature and validate by parsing.
            // (Used for raw LE images without an MZ container.)
            for (var i = 0; i <= fileBytes.Length - 4; i++)
            {
                if (fileBytes[i] != (byte)'L' || fileBytes[i + 1] != (byte)'E' || fileBytes[i + 2] != 0x00 || fileBytes[i + 3] != 0x00)
                    continue;

                if (TryParseHeader(fileBytes, i, out var _, out var _))
                {
                    offset = i;
                    return true;
                }
            }

            offset = 0;
            return false;
        }

        private static bool TryScanForLeHeaderInMzOverlay(byte[] fileBytes, out int leHeaderOffset)
        {
            leHeaderOffset = 0;
            if (fileBytes == null || fileBytes.Length < 0x40)
                return false;
            if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
                return false;

            // Compute the overlay base (load module size) from the outer MZ header.
            // This intentionally avoids scanning the MZ stub body.
            var eCblp = ReadUInt16(fileBytes, 0x02);
            var eCp = ReadUInt16(fileBytes, 0x04);
            if (eCp == 0)
                return false;

            var overlayBaseL = ((long)eCp - 1) * 512L + (eCblp == 0 ? 512L : eCblp);
            if (overlayBaseL < 0x40 || overlayBaseL >= fileBytes.Length)
                return false;

            var start = (int)overlayBaseL;
            for (var i = start; i <= fileBytes.Length - 4; i++)
            {
                if (fileBytes[i] != (byte)'L' || fileBytes[i + 1] != (byte)'E' || fileBytes[i + 2] != 0x00 || fileBytes[i + 3] != 0x00)
                    continue;

                if (TryParseHeader(fileBytes, i, out var _, out var _))
                {
                    leHeaderOffset = i;
                    return true;
                }
            }

            return false;
        }

        private static bool TryFindEmbeddedLeOffsetFromBwOverlay(byte[] fileBytes, out int leHeaderOffset)
        {
            leHeaderOffset = 0;
            if (fileBytes == null || fileBytes.Length < 0x40)
                return false;
            if (fileBytes[0] != (byte)'M' || fileBytes[1] != (byte)'Z')
                return false;

            // Compute the overlay base (load module size) from the outer MZ header.
            var eCblp = ReadUInt16(fileBytes, 0x02);
            var eCp = ReadUInt16(fileBytes, 0x04);
            if (eCp == 0)
                return false;

            var overlayBaseL = ((long)eCp - 1) * 512L + (eCblp == 0 ? 512L : eCblp);
            if (overlayBaseL < 0x40 || overlayBaseL + 4 > fileBytes.Length)
                return false;
            var overlayBase = (int)overlayBaseL;

            // BW overlay header signature.
            if (fileBytes[overlayBase] != (byte)'B' || fileBytes[overlayBase + 1] != (byte)'W')
                return false;

            var bwHeaderLen = (int)ReadUInt16(fileBytes, overlayBase + 2);
            if (bwHeaderLen <= 0 || bwHeaderLen > 64 * 1024)
                return false;
            if (overlayBase + bwHeaderLen > fileBytes.Length)
                return false;

            // Heuristic: scan BW header u32 fields for a relative pointer to an embedded MZ which itself is bound to LE.
            for (var fieldOff = 0; fieldOff + 4 <= bwHeaderLen; fieldOff += 4)
            {
                var rel = ReadUInt32(fileBytes, overlayBase + fieldOff);
                if (rel == 0)
                    continue;

                var innerMzOffL = overlayBaseL + rel;
                if (innerMzOffL < 0 || innerMzOffL + 0x40 > fileBytes.Length)
                    continue;
                var innerMzOff = (int)innerMzOffL;

                if (fileBytes[innerMzOff] != (byte)'M' || fileBytes[innerMzOff + 1] != (byte)'Z')
                    continue;

                var innerLfanew = ReadUInt32(fileBytes, innerMzOff + 0x3C);
                if (innerLfanew < 0x40)
                    continue;

                var innerLeOffL = innerMzOffL + innerLfanew;
                if (innerLeOffL < 0 || innerLeOffL + 4 > fileBytes.Length)
                    continue;
                var innerLeOff = (int)innerLeOffL;

                if (fileBytes[innerLeOff] == (byte)'L' &&
                    fileBytes[innerLeOff + 1] == (byte)'E' &&
                    fileBytes[innerLeOff + 2] == 0x00 &&
                    fileBytes[innerLeOff + 3] == 0x00)
                {
                    leHeaderOffset = innerLeOff;
                    return true;
                }
            }

            return false;
        }

        private static bool TryParseHeader(byte[] fileBytes, int headerOffset, out LEHeader header, out string error)
        {
            header = default;
            error = string.Empty;

            if (headerOffset < 0 || headerOffset + 0x84 > fileBytes.Length)
            {
                error = "Invalid LE header offset";
                return false;
            }

            if (fileBytes[headerOffset] != (byte)'L' || fileBytes[headerOffset + 1] != (byte)'E')
            {
                error = "Invalid LE signature";
                return false;
            }

            // byte order + word order are 0 for little endian
            var byteOrder = ReadUInt16(fileBytes, headerOffset + 0x02);
            var wordOrder = ReadUInt16(fileBytes, headerOffset + 0x04);
            if (byteOrder != 0 || wordOrder != 0)
            {
                error = "Unsupported LE byte/word order";
                return false;
            }

            header.HeaderOffset = headerOffset;

            header.ModuleFlags = ReadUInt32(fileBytes, headerOffset + 0x10);
            header.NumberOfPages = ReadUInt32(fileBytes, headerOffset + 0x14);
            header.EntryEipObject = ReadUInt32(fileBytes, headerOffset + 0x18);
            header.EntryEip = ReadUInt32(fileBytes, headerOffset + 0x1C);
            header.EntryEspObject = ReadUInt32(fileBytes, headerOffset + 0x20);
            header.EntryEsp = ReadUInt32(fileBytes, headerOffset + 0x24);
            header.PageSize = ReadUInt32(fileBytes, headerOffset + 0x28);
            header.LastPageSize = ReadUInt32(fileBytes, headerOffset + 0x2C);

            header.ObjectTableOffset = ReadUInt32(fileBytes, headerOffset + 0x40);
            header.ObjectCount = ReadUInt32(fileBytes, headerOffset + 0x44);
            header.ObjectPageMapOffset = ReadUInt32(fileBytes, headerOffset + 0x48);

            header.FixupPageTableOffset = ReadUInt32(fileBytes, headerOffset + 0x68);
            header.FixupRecordTableOffset = ReadUInt32(fileBytes, headerOffset + 0x6C);

            // Best-effort: import tables (offsets are relative to LE header)
            header.ImportModuleTableOffset = ReadUInt32(fileBytes, headerOffset + 0x70);
            header.ImportModuleTableEntries = ReadUInt32(fileBytes, headerOffset + 0x74);
            header.ImportProcTableOffset = ReadUInt32(fileBytes, headerOffset + 0x78);

            header.DataPagesOffset = ReadUInt32(fileBytes, headerOffset + 0x80);

            if (header.PageSize == 0 || header.ObjectCount == 0 || header.NumberOfPages == 0)
            {
                error = "Invalid LE header (zero PageSize/ObjectCount/PageCount)";
                return false;
            }

            // If last page size is 0, treat it as full page size per spec conventions.
            if (header.LastPageSize == 0)
                header.LastPageSize = header.PageSize;

            _logger.Info($"Detected LE header at 0x{headerOffset:X} (Objects={header.ObjectCount}, Pages={header.NumberOfPages}, PageSize={header.PageSize})");
            return true;
        }

        private static List<string> TryParseImportModules(byte[] fileBytes, LEHeader header)
        {
            try
            {
                if (header.ImportModuleTableOffset == 0 || header.ImportModuleTableEntries == 0)
                    return null;

                var start = header.HeaderOffset + (int)header.ImportModuleTableOffset;
                if (start < 0 || start >= fileBytes.Length)
                    return null;

                var modules = new List<string>((int)Math.Min(header.ImportModuleTableEntries, 4096));
                var off = start;
                for (var i = 0; i < header.ImportModuleTableEntries; i++)
                {
                    if (off >= fileBytes.Length)
                        break;
                    var len = fileBytes[off];
                    off++;
                    if (len == 0)
                    {
                        modules.Add(string.Empty);
                        continue;
                    }
                    if (off + len > fileBytes.Length)
                        break;
                    var name = Encoding.ASCII.GetString(fileBytes, off, len);
                    modules.Add(name);
                    off += len;
                }

                return modules;
            }
            catch
            {
                return null;
            }
        }

        private static string TryReadImportProcName(byte[] fileBytes, LEHeader header, uint procNameOffset)
        {
            try
            {
                if (header.ImportProcTableOffset == 0)
                    return string.Empty;

                var baseOff = header.HeaderOffset + (int)header.ImportProcTableOffset;
                var off = baseOff + (int)procNameOffset;
                if (off < 0 || off >= fileBytes.Length)
                    return string.Empty;
                var len = fileBytes[off];
                off++;
                if (len == 0)
                    return string.Empty;
                if (off + len > fileBytes.Length)
                    return string.Empty;
                return Encoding.ASCII.GetString(fileBytes, off, len);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool TryGetFixupStreams(byte[] fileBytes, LEHeader header, out uint[] fixupPageOffsets, out byte[] fixupRecordStream)
        {
            fixupPageOffsets = null;
            fixupRecordStream = null;

            try
            {
                if (header.FixupPageTableOffset == 0 || header.FixupRecordTableOffset == 0 || header.NumberOfPages == 0)
                    return false;

                var pageTableStart = header.HeaderOffset + (int)header.FixupPageTableOffset;
                var recordStart = header.HeaderOffset + (int)header.FixupRecordTableOffset;
                if (pageTableStart < 0 || pageTableStart >= fileBytes.Length)
                    return false;
                if (recordStart < 0 || recordStart >= fileBytes.Length)
                    return false;

                var count = checked((int)header.NumberOfPages + 1);
                var offsets = new uint[count];
                for (var i = 0; i < count; i++)
                {
                    var off = pageTableStart + i * 4;
                    if (off + 4 > fileBytes.Length)
                        return false;
                    offsets[i] = ReadUInt32(fileBytes, off);
                }

                var total = offsets[count - 1];
                if (total == 0)
                    return false;
                if (recordStart + total > fileBytes.Length)
                    total = (uint)Math.Max(0, fileBytes.Length - recordStart);

                var records = new byte[total];
                Buffer.BlockCopy(fileBytes, recordStart, records, 0, (int)total);

                fixupPageOffsets = offsets;
                fixupRecordStream = records;
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool TryMapLinearToObject(List<LEObject> objects, uint linear, out int objIndex, out uint offset)
        {
            objIndex = 0;
            offset = 0;

            if (objects == null || objects.Count == 0)
                return false;

            // Objects are typically few (here: 3), so linear scan is fine.
            foreach (var obj in objects)
            {
                if (obj.VirtualSize == 0)
                    continue;

                // Allow a small slack for references that land in padding past VirtualSize.
                var end = unchecked(obj.BaseAddress + obj.VirtualSize + 0x1000);
                if (linear >= obj.BaseAddress && linear < end)
                {
                    objIndex = obj.Index;
                    offset = unchecked(linear - obj.BaseAddress);
                    return true;
                }
            }

            return false;
        }

        private static List<LEObject> ParseObjects(byte[] fileBytes, LEHeader header)
        {
            var objects = new List<LEObject>((int)header.ObjectCount);

            var objectTableStart = header.HeaderOffset + (int)header.ObjectTableOffset;
            for (var i = 0; i < header.ObjectCount; i++)
            {
                var entryOffset = objectTableStart + i * LE_OBJECT_ENTRY_SIZE;
                if (entryOffset + LE_OBJECT_ENTRY_SIZE > fileBytes.Length)
                    break;

                // LE object entry is 6x uint32
                var virtualSize = ReadUInt32(fileBytes, entryOffset + 0x00);
                var baseAddress = ReadUInt32(fileBytes, entryOffset + 0x04);
                var flags = ReadUInt32(fileBytes, entryOffset + 0x08);
                var pageMapIndex = ReadUInt32(fileBytes, entryOffset + 0x0C);
                var pageCount = ReadUInt32(fileBytes, entryOffset + 0x10);

                objects.Add(new LEObject
                {
                    Index = i + 1,
                    VirtualSize = virtualSize,
                    BaseAddress = baseAddress,
                    Flags = flags,
                    PageMapIndex = pageMapIndex,
                    PageCount = pageCount
                });
            }

            return objects;
        }

        private static uint[] ParseObjectPageMap(byte[] fileBytes, LEHeader header)
        {
            var pageMapStart = header.HeaderOffset + (int)header.ObjectPageMapOffset;
            var map = new uint[header.NumberOfPages];

            for (var i = 0; i < map.Length; i++)
            {
                var off = pageMapStart + i * 4;
                if (off + 4 > fileBytes.Length)
                    break;

                // LE object page map entries are 4 bytes.
                // For DOS4GW-style LEs, the physical page number is stored as a 16-bit value in the upper word.
                // (The lower word is typically flags.)
                map[i] = ReadUInt16(fileBytes, off + 2);
            }

            return map;
        }

        private static byte[] ReconstructObjectBytes(byte[] fileBytes, LEHeader header, uint[] pageMap, int dataPagesBase, LEObject obj)
        {
            var pageSize = (int)header.PageSize;
            var totalLen = checked((int)obj.PageCount * pageSize);
            var buf = new byte[totalLen];

            for (var i = 0; i < obj.PageCount; i++)
            {
                var pageMapIndex0 = (int)obj.PageMapIndex - 1 + i;
                if (pageMapIndex0 < 0 || pageMapIndex0 >= pageMap.Length)
                    break;

                var physicalPage = pageMap[pageMapIndex0]; // 1-based
                if (physicalPage == 0)
                    continue;

                var isLastModulePage = physicalPage == header.NumberOfPages;
                var bytesThisPage = isLastModulePage ? (int)header.LastPageSize : pageSize;

                var pageFileOffset = dataPagesBase + (int)(physicalPage - 1) * pageSize;
                if (pageFileOffset < 0 || pageFileOffset >= fileBytes.Length)
                    break;

                var available = Math.Min(bytesThisPage, fileBytes.Length - pageFileOffset);
                if (available <= 0)
                    break;

                Buffer.BlockCopy(fileBytes, pageFileOffset, buf, i * pageSize, available);
            }

            return buf;
        }

        private static ushort ReadUInt16(byte[] data, int offset)
        {
            return (ushort)(data[offset] | (data[offset + 1] << 8));
        }

        private static uint ReadUInt32(byte[] data, int offset)
        {
            return (uint)(data[offset] |
                          (data[offset + 1] << 8) |
                          (data[offset + 2] << 16) |
                          (data[offset + 3] << 24));
        }

        private static string HexDump(byte[] data, int offset, int length, int bytesPerLine = 16)
        {
            if (data == null || length <= 0)
                return string.Empty;

            var sb = new StringBuilder();
            var end = Math.Min(data.Length, offset + length);
            for (var i = offset; i < end; i += bytesPerLine)
            {
                var lineLen = Math.Min(bytesPerLine, end - i);
                sb.Append(";   ");
                sb.Append($"0x{(i - offset):X4}: ");
                for (var j = 0; j < lineLen; j++)
                {
                    sb.Append(data[i + j].ToString("X2"));
                    if (j + 1 < lineLen)
                        sb.Append(' ');
                }
                sb.AppendLine();
            }
            return sb.ToString().TrimEnd();
        }
    }
}
