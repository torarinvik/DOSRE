using Xunit;
using DOSRE.Dasm;

namespace DOSRE.Tests
{
    public class WatcomDemanglerTests
    {
        [Theory]
        [InlineData("?MyFunc$qipv", "MyFunc(int, void*)")]
        [InlineData("?MyValue$i", "int MyValue")]
        [InlineData("?Add$qii", "Add(int, int)")]
        [InlineData("?ProcessData$qpxcuc", "ProcessData(char const*, unsigned char)")]
        [InlineData("?GetData$qrv", "GetData(void&)")]
        [InlineData("?SetTimeout$ql", "SetTimeout(long)")]
        [InlineData("W?WideFunc$qv", "WideFunc(void)")]
        [InlineData("PlainName", "PlainName")]
        public void TestDemangle(string mangled, string expected)
        {
            var result = LEDisassembler.DemangleWatcom(mangled);
            Assert.Equal(expected, result);
        }
    }
}
