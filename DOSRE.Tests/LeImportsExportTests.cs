using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeImportsExportTests
    {
        [Fact]
        public void BuildImportMapExport_GroupsImportsAndMapsSitesToFunctions()
        {
            var table = new LEDisassembler.LeFixupTableInfo
            {
                inputFile = "test.exe",
                entryLinear = 0x1000,
                pageSize = 0x1000,
                numberOfPages = 1,
                importModules = new[] { "KERNEL" },
                fixups = new[]
                {
                    new LEDisassembler.LeFixupRecordInfo
                    {
                        targetKind = "import",
                        siteLinear = 0x1010,
                        importModuleIndex = 0,
                        importModule = "KERNEL",
                        importProcNameOffset = 0x20,
                        importProc = "Foo"
                    },
                    new LEDisassembler.LeFixupRecordInfo
                    {
                        targetKind = "import",
                        siteLinear = 0x2010,
                        importModuleIndex = 0,
                        importModule = "KERNEL",
                        importProcNameOffset = 0x20,
                        importProc = "Foo"
                    }
                }
            };

            var analysis = new LEDisassembler.LeAnalysis { InputFile = "test.exe", EntryLinear = 0x1000 };
            analysis.Functions[0x1000] = new LEDisassembler.LeFunctionInfo { Start = 0x1000 };
            analysis.Functions[0x2000] = new LEDisassembler.LeFunctionInfo { Start = 0x2000 };

            var payload = LeExports.BuildImportMapExport(table, analysis);

            Assert.Equal("test.exe", payload.input);
            Assert.Equal("0x00001000", payload.entry);
            Assert.Equal(1, payload.moduleCount);
            Assert.Equal(1, payload.procCount);
            Assert.Equal(2, payload.xrefCount);

            Assert.NotNull(payload.modules);
            Assert.Single(payload.modules);
            Assert.Equal(0, payload.modules[0].index);
            Assert.Equal("KERNEL", payload.modules[0].name);
            Assert.Equal(1, payload.modules[0].procCount);

            Assert.NotNull(payload.modules[0].procs);
            Assert.Single(payload.modules[0].procs);

            var p = payload.modules[0].procs[0];
            Assert.Equal(0, p.moduleIndex);
            Assert.Equal("KERNEL", p.module);
            Assert.Equal("0x20", p.procNameOffset);
            Assert.Equal("Foo", p.name);
            Assert.Equal(2, p.xrefCount);
            Assert.Equal(new[] { "0x00001010", "0x00002010" }, p.sites);
            Assert.Equal(new[] { "0x00001000", "0x00002000" }, p.functions);
        }
    }
}
