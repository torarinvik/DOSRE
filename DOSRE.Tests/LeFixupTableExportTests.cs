using System;
using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeFixupTableExportTests
    {
        [Fact]
        public void BuildFixupTableExport_FormatsAndSortsDeterministically()
        {
            var table = new LEDisassembler.LeFixupTableInfo
            {
                inputFile = "test.exe",
                entryLinear = 0x11223344,
                pageSize = 0x1000,
                numberOfPages = 3,
                objects = new[]
                {
                    new LEDisassembler.LeObjectInfo
                    {
                        index = 2,
                        baseAddress = 0x3000,
                        virtualSize = 0x20,
                        flags = 0xAABBCCDD,
                        pageMapIndex = 9,
                        pageCount = 1
                    },
                    new LEDisassembler.LeObjectInfo
                    {
                        index = 1,
                        baseAddress = 0x1000,
                        virtualSize = 0x10,
                        flags = 0x00000001,
                        pageMapIndex = 7,
                        pageCount = 2
                    }
                },
                importModules = new[] { "KERNEL", "DOS4GW" },
                fixups = new[]
                {
                    new LEDisassembler.LeFixupRecordInfo
                    {
                        siteLinear = 0x2000,
                        sourceLinear = 0x2000,
                        siteDelta = -1,
                        logicalPageNumber = 2,
                        physicalPageNumber = 5,
                        type = 0x7F,
                        flags = 0x80,
                        recordStreamOffset = 20,
                        stride = 16,
                        targetKind = "import",
                        importModuleIndex = 1,
                        importModule = "DOS4GW",
                        importProcNameOffset = 0x123,
                        importProc = "_dos4gw_init"
                    },
                    new LEDisassembler.LeFixupRecordInfo
                    {
                        siteLinear = 0x1000,
                        sourceLinear = 0x1000,
                        instructionLinear = 0x1000,
                        siteDelta = 2,
                        logicalPageNumber = 1,
                        physicalPageNumber = 4,
                        type = 0x01,
                        flags = 0x02,
                        recordStreamOffset = 10,
                        stride = 8,
                        targetKind = "internal",
                        targetObject = 2,
                        targetOffset = 0x10,
                        targetLinear = 0x3010,
                        addend32 = 4,
                        siteValue32 = 0x300C
                    }
                },
                chains = new[]
                {
                    new LEDisassembler.LeFixupChainInfo
                    {
                        targetKind = "internal",
                        targetObject = 2,
                        targetOffset = 0x10,
                        targetLinear = 0x3010,
                        count = 1
                    },
                    new LEDisassembler.LeFixupChainInfo
                    {
                        targetKind = "import",
                        importModuleIndex = 1,
                        importProcNameOffset = 0x123,
                        count = 1
                    }
                }
            };

            var payload = LeExports.BuildFixupTableExport(table);

            Assert.Equal("test.exe", payload.input);
            Assert.Equal("0x11223344", payload.entry);
            Assert.Equal("func_11223344", payload.entryName);
            Assert.Equal("0x1000", payload.pageSize);
            Assert.Equal(3, payload.pages);

            // Objects are sorted by index.
            Assert.NotNull(payload.objects);
            Assert.Equal(2, payload.objects.Length);
            Assert.Equal(1, payload.objects[0].index);
            Assert.Equal("0x00001000", payload.objects[0].baseAddress);
            Assert.Equal(2, payload.objects[1].index);

            // Fixups are sorted by siteLinear then recordStreamOffset.
            Assert.Equal(2, payload.fixupCount);
            Assert.NotNull(payload.fixups);
            Assert.Equal("0x00001000", payload.fixups[0].site);
            Assert.Equal("0x01", payload.fixups[0].type);
            Assert.Equal("0x0000300C", payload.fixups[0].siteValue32);
            Assert.Equal("0x00001000", payload.fixups[0].instructionLinear);
            Assert.Equal("internal", payload.fixups[0].targetKind);
            Assert.Equal("0x10", payload.fixups[0].targetOffset);
            Assert.Equal("0x00003010", payload.fixups[0].targetLinear);
            Assert.Equal(2, payload.fixups[0].delta);

            Assert.Equal("0x00002000", payload.fixups[1].site);
            Assert.Equal("import", payload.fixups[1].targetKind);
            Assert.Equal(-1, payload.fixups[1].delta);
            Assert.Equal(1, payload.fixups[1].importModuleIndex);
            Assert.Equal("0x123", payload.fixups[1].importProcNameOffset);
        }

        [Fact]
        public void BuildFixupTableExport_IncludesRawRecordFields_WhenProvided()
        {
            var table = new LEDisassembler.LeFixupTableInfo
            {
                inputFile = "X",
                entryLinear = 0x00001000u,
                pageSize = 0x1000,
                numberOfPages = 1,
                objects = Array.Empty<LEDisassembler.LeObjectInfo>(),
                fixups = new[]
                {
                    new LEDisassembler.LeFixupRecordInfo
                    {
                        siteLinear = 0x00001000u,
                        sourceLinear = 0x00001000u,
                        logicalPageNumber = 1,
                        physicalPageNumber = 1,
                        type = 0x07,
                        flags = 0x00,
                        recordStreamOffset = 123,
                        stride = 8,
                        recordBytes = new byte[] { 0x07, 0x00, 0x48, 0x00, 0x07, 0x00, 0x46, 0x00 },
                        specU16 = 0x0007,
                        specU16b = 0x0046,
                        specU32 = null,
                        targetKind = "unknown"
                    }
                },
                chains = Array.Empty<LEDisassembler.LeFixupChainInfo>()
            };

            var payload = LeExports.BuildFixupTableExport(table);
            Assert.NotNull(payload.fixups);
            Assert.Single(payload.fixups);

            var f = payload.fixups[0];
            Assert.Equal("0700480007004600", f.recordBytes);
            Assert.Equal("0x0007", f.specU16);
            Assert.Equal("0x0046", f.specU16b);
            Assert.Null(f.specU32);
        }
    }
}
