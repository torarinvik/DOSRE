using System;
using System.IO;
using System.Linq;
using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeFixupTableIntegrationTests
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
        public void TryBuildFixupTable_CLIENT_EXE_ProducesDeterministicExport()
        {
            // Locate repo root from test output directory.
            var repoRoot = FindRepoRoot(AppContext.BaseDirectory);
            if (string.IsNullOrWhiteSpace(repoRoot))
                return;

            var input = Path.Combine(repoRoot, "EXES", "CLIENT.EXE");
            if (!File.Exists(input))
                return;

            LeExports.LeFixupTableExport? payload = null;
            string? json = null;

            try
            {
                var ok = LEDisassembler.TryBuildFixupTable(input, leScanMzOverlayFallback: true, out var table, out var err);
                Assert.True(ok, err);
                Assert.NotNull(table);

                payload = LeExports.BuildFixupTableExport(table);
                Assert.NotNull(payload);
                Assert.Equal(input, payload.input);

                // Ensure JSON serialization is stable (doesn't throw and yields non-empty output).
                json = System.Text.Json.JsonSerializer.Serialize(payload, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                });
                Assert.False(string.IsNullOrWhiteSpace(json));
                Assert.Contains("\"input\"", json);
            }
            catch (Exception ex)
            {
                if (!string.IsNullOrWhiteSpace(json))
                {
                    var fileName = $"dosre.fixups.CLIENT.{DateTime.UtcNow:yyyyMMddHHmmss}.json";
                    var path = Path.Combine(Path.GetTempPath(), fileName);
                    File.WriteAllText(path, json);
                    Console.WriteLine($"Wrote debug fixup-table JSON to: {path} (due to test failure: {ex.Message})");
                }
                throw;
            }

            // Basic sanity: if there are fixups, ensure they are deterministically ordered.
            if (payload.fixups != null && payload.fixups.Length > 0)
            {
                Assert.Equal(payload.fixupCount, payload.fixups.Length);

                long Key(string hex) => Convert.ToInt64(hex.StartsWith("0x", StringComparison.Ordinal) ? hex.Substring(2) : hex, 16);

                for (var i = 1; i < payload.fixups.Length; i++)
                {
                    var prev = payload.fixups[i - 1];
                    var cur = payload.fixups[i];

                    var prevSite = Key(prev.site);
                    var curSite = Key(cur.site);
                    if (curSite < prevSite)
                        Assert.Fail("Fixups are not sorted by site address");

                    if (curSite == prevSite && cur.recordStreamOffset < prev.recordStreamOffset)
                        Assert.Fail("Fixups are not sorted by recordStreamOffset within the same site address");
                }

                // Shape checks for hex formatting.
                Assert.All(payload.fixups, f => Assert.StartsWith("0x", f.site));
                Assert.All(payload.fixups, f => Assert.StartsWith("0x", f.source));
                Assert.All(payload.fixups, f => Assert.StartsWith("0x", f.type));
                Assert.All(payload.fixups, f => Assert.StartsWith("0x", f.flags));
            }
            else
            {
                Assert.Equal(0, payload.fixupCount);
            }
        }

        [Fact]
        public void TryBuildFixupTable_HELLO_EXE_ReducesUnknownFixups()
        {
            // Locate repo root from test output directory.
            var repoRoot = FindRepoRoot(AppContext.BaseDirectory);
            if (string.IsNullOrWhiteSpace(repoRoot))
                return;

            var input = Path.Combine(repoRoot, "EXES", "HELLO.EXE");
            if (!File.Exists(input))
                return;

            var ok = LEDisassembler.TryBuildFixupTable(input, leScanMzOverlayFallback: true, out var table, out var err);
            Assert.True(ok, err);
            Assert.NotNull(table);

            var payload = LeExports.BuildFixupTableExport(table);
            Assert.NotNull(payload);
            Assert.Equal(input, payload.input);

            var unknown = payload.fixups?.Count(f => string.Equals(f.targetKind, "unknown", StringComparison.Ordinal)) ?? 0;

            // Historically HELLO had the vast majority of fixups classified as unknown.
            // Keep this somewhat loose (to avoid brittleness), but it should remain very low as decoding improves.
            Assert.True(unknown <= 5, $"Too many unknown fixups: {unknown}");
        }
    }
}
