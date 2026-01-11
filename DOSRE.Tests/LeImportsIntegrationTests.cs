using System;
using System.IO;
using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeImportsIntegrationTests
    {
        private static string FindRepoRoot(string startDir)
        {
            var dir = new DirectoryInfo(startDir);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "DOSRE.sln")))
                    return dir.FullName;
                dir = dir.Parent;
            }
            return string.Empty;
        }

        [Fact]
        public void BuildImportMapExport_CLIENT_EXE_DoesNotThrow()
        {
            var repoRoot = FindRepoRoot(AppContext.BaseDirectory);
            if (string.IsNullOrWhiteSpace(repoRoot))
                return;

            var input = Path.Combine(repoRoot, "EXES", "CLIENT.EXE");
            if (!File.Exists(input))
                return;

            Assert.True(LEDisassembler.TryBuildFixupTable(input, leScanMzOverlayFallback: true, out var table, out var err), err);
            var payload = LeExports.BuildImportMapExport(table);
            Assert.NotNull(payload);
            Assert.Equal(input, payload.input);
            Assert.True(payload.moduleCount >= 0);
            Assert.True(payload.procCount >= 0);
            Assert.True(payload.xrefCount >= 0);
        }
    }
}
