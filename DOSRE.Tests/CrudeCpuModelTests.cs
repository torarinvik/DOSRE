using System.IO;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class CrudeCpuModelTests
    {
        [Fact]
        public void Step_MovAxCs_UpdatesAx()
        {
            var fixture = Path.Combine(System.AppContext.BaseDirectory, "Fixtures", "binlift", "sample.promoted.asm");
            var lines = File.ReadAllLines(fixture);
            var lf = Bin16AsmLifter.LiftLines(lines, fixture);

            var s = new CrudeCpuModel.State { CS = 0x1234, IP = 0x0000 };
            var n0 = lf.Nodes.Find(n => n.Kind == "insn" && n.Addr == 0x00000000);

            Assert.True(CrudeCpuModel.TryStep(s, n0, out var ev, out var err), err);
            Assert.Null(ev);
            Assert.Equal((ushort)0x1234, s.AX);
        }

        [Fact]
        public void Step_Int21_EmitsEvent()
        {
            var fixture = Path.Combine(System.AppContext.BaseDirectory, "Fixtures", "binlift", "sample.promoted.asm");
            var lines = File.ReadAllLines(fixture);
            var lf = Bin16AsmLifter.LiftLines(lines, fixture);

            var s = new CrudeCpuModel.State { IP = 0x0004 };
            var n = lf.Nodes.Find(x => x.Kind == "insn" && x.Addr == 0x00000004);

            Assert.True(CrudeCpuModel.TryStep(s, n, out var ev, out var err), err);
            Assert.NotNull(ev);
            Assert.Equal("int", ev.Kind);
            Assert.Equal("0x21", ev.Detail);
        }
    }
}
