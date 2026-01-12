using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        public static bool TryDumpFixupsToString(string inputFile, int? maxPages, int maxBytesPerPage, out string output, out string error)
        {
            return TryDumpFixupsToString(inputFile, maxPages, maxBytesPerPage, leScanMzOverlayFallback: false, out output, out error);
        }

        public static bool TryDumpFixupsToString(string inputFile, int? maxPages, int maxBytesPerPage, bool leScanMzOverlayFallback, out string output, out string error)
        {
            output = string.Empty;
            error = string.Empty;

            if (!File.Exists(inputFile))
            {
                error = "Input file not found";
                return false;
            }

            if (maxBytesPerPage <= 0)
                maxBytesPerPage = 256;

            var fileBytes = File.ReadAllBytes(inputFile);
            if (!TryFindLEHeaderOffset(fileBytes, allowMzOverlayScanFallback: leScanMzOverlayFallback, out var leHeaderOffset))
            {
                error = "LE header not found";
                return false;
            }

            if (!TryParseHeader(fileBytes, leHeaderOffset, out var header, out error))
                return false;

            var objects = ParseObjects(fileBytes, header);
            var pageMap = ParseObjectPageMap(fileBytes, header);

            var sb = new StringBuilder();
            sb.AppendLine($"; LE FIXUP DUMP (DOS4GW-focused) - {Path.GetFileName(inputFile)}");
            sb.AppendLine($"; HeaderOffset: 0x{header.HeaderOffset:X}");
            sb.AppendLine($"; Pages: {header.NumberOfPages}  PageSize: {header.PageSize}  LastPageSize: {header.LastPageSize}");
            sb.AppendLine($"; FixupPageTableOffset: 0x{header.FixupPageTableOffset:X}  FixupRecordTableOffset: 0x{header.FixupRecordTableOffset:X}");
            sb.AppendLine($"; ImportModuleTableOffset: 0x{header.ImportModuleTableOffset:X}  Entries: {header.ImportModuleTableEntries}");
            sb.AppendLine($"; ImportProcTableOffset: 0x{header.ImportProcTableOffset:X}");
            sb.AppendLine(";");

            var importModules = TryParseImportModules(fileBytes, header);
            if (importModules != null && importModules.Count > 0)
            {
                sb.AppendLine("; Import Modules");
                for (var i = 0; i < importModules.Count; i++)
                {
                    var name = string.IsNullOrEmpty(importModules[i]) ? "(empty)" : importModules[i];
                    sb.AppendLine($";   [{i + 1}] {name}");
                }
                sb.AppendLine(";");
            }

            if (!TryGetFixupStreams(fileBytes, header, out var fixupPageOffsets, out var fixupRecordStream) || fixupPageOffsets == null || fixupRecordStream == null)
            {
                sb.AppendLine("; No fixup streams available (or failed to parse fixup tables)");
                output = sb.ToString();
                return true;
            }

            var recordFileStart = header.HeaderOffset + (int)header.FixupRecordTableOffset;
            sb.AppendLine($"; Fixup record stream length: 0x{fixupRecordStream.Length:X} ({fixupRecordStream.Length} bytes)");
            sb.AppendLine($"; Fixup record stream file offset: 0x{recordFileStart:X}");
            sb.AppendLine(";");

            sb.AppendLine("; Objects (for context)");
            foreach (var obj in objects)
                sb.AppendLine($";   Obj{obj.Index} Base=0x{obj.BaseAddress:X8} Size=0x{obj.VirtualSize:X} PageMapIndex={obj.PageMapIndex} PageCount={obj.PageCount} Flags=0x{obj.Flags:X8}");
            sb.AppendLine(";");

            var pagesToDump = (int)header.NumberOfPages;
            if (maxPages.HasValue && maxPages.Value > 0)
                pagesToDump = Math.Min(pagesToDump, maxPages.Value);

            sb.AppendLine("; Per-page fixup slices");
            sb.AppendLine("; NOTE: LE fixup page table is indexed by *logical page number* (1..NumberOfPages)");
            sb.AppendLine("; NOTE: Below includes a stride auto-detect (candidates: 8/10/12/16) and a stride-based view.");
            sb.AppendLine(";");

            var strideCounts = new Dictionary<int, int>();

            for (var page1 = 1; page1 <= pagesToDump; page1++)
            {
                var idx0 = page1 - 1;
                if (idx0 + 1 >= fixupPageOffsets.Length)
                    break;

                var start = fixupPageOffsets[idx0];
                var end = fixupPageOffsets[idx0 + 1];
                if (end <= start)
                    continue;

                if (end > (uint)fixupRecordStream.Length)
                    continue;

                var len = (int)(end - start);
                sb.AppendLine($"; -------- Page {page1} --------");
                sb.AppendLine($"; RecordStreamOff: 0x{start:X}..0x{end:X} (len=0x{len:X})");

                var strideGuess = GuessStride(fixupRecordStream, (int)start, len, (int)header.PageSize);
                if (!strideCounts.ContainsKey(strideGuess.Stride))
                    strideCounts[strideGuess.Stride] = 0;
                strideCounts[strideGuess.Stride]++;
                sb.AppendLine($"; Best stride guess: {strideGuess.Stride} bytes (score={strideGuess.Score:0.00}, validSrcOff={strideGuess.ValidSrcOff}/{strideGuess.EntriesChecked})");

                // Raw hexdump (capped)
                var dumpLen = Math.Min(len, maxBytesPerPage);
                sb.AppendLine($"; Raw bytes (first {dumpLen} of {len})");
                sb.AppendLine(HexDump(fixupRecordStream, (int)start, dumpLen));

                sb.AppendLine($"; Stride-based view (stride={strideGuess.Stride})");
                sb.AppendLine(DumpStrideView(fixupRecordStream, (int)start, (int)end, strideGuess.Stride, 64));

                sb.AppendLine(";");
            }

            if (strideCounts.Count > 0)
            {
                sb.AppendLine("; -------- Stride summary --------");
                foreach (var kvp in strideCounts.OrderBy(k => k.Key))
                    sb.AppendLine($"; stride {kvp.Key}: {kvp.Value} page(s)");
                sb.AppendLine(";");
            }

            output = sb.ToString();
            return true;
        }
    }
}
