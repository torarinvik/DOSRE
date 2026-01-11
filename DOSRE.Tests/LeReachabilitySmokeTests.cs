using System;
using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeReachabilitySmokeTests
    {
        [Fact]
        public void Reachability_OnRealClientExe_ProducesNonEmptyObjects_WhenPresent()
        {
            var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.."));
            var clientExe = Path.Combine(repoRoot, "EXES", "CLIENT.EXE");

            if (!File.Exists(clientExe))
            {
                return; // smoke test only; skip when binary not present
            }

            Assert.True(LEDisassembler.TryBuildReachabilityMap(clientExe, leScanMzOverlayFallback: true, out var map, out var error), error);
            Assert.NotNull(map.objects);
            Assert.True(map.objects.Length > 0);

            // Basic invariants.
            foreach (var obj in map.objects)
            {
                Assert.True(obj.virtualSize >= 0);
                Assert.True(obj.decodedEndLinear >= obj.decodedStartLinear);
                Assert.True(obj.reachableByteCount >= 0);
            }
        }
    }
}
