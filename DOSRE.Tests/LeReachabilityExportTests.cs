using DOSRE.Analysis;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeReachabilityExportTests
    {
        [Fact]
        public void BuildReachabilityExport_FormatsDeterministically()
        {
            var map = new LEDisassembler.LeReachabilityInfo
            {
                inputFile = "test.exe",
                entryLinear = 0x11223344,
                objects = new[]
                {
                    new LEDisassembler.LeReachabilityObjectInfo
                    {
                        index = 2,
                        baseAddress = 0x3000,
                        virtualSize = 0x20,
                        flags = 0xAABBCCDD,
                        decodedStartLinear = 0x3000,
                        decodedEndLinear = 0x3020,
                        instructionCount = 10,
                        reachableInstructionCount = 3,
                        reachableByteCount = 7,
                        reachableCodeRanges = new[]
                        {
                            new LEDisassembler.LeReachabilityRangeInfo { startLinear = 0x3000, endLinear = 0x3003 },
                            new LEDisassembler.LeReachabilityRangeInfo { startLinear = 0x3010, endLinear = 0x3014 },
                        },
                        dataCandidateRanges = new[]
                        {
                            new LEDisassembler.LeReachabilityRangeInfo { startLinear = 0x3003, endLinear = 0x3010 },
                        }
                    },
                    new LEDisassembler.LeReachabilityObjectInfo
                    {
                        index = 1,
                        baseAddress = 0x1000,
                        virtualSize = 0x10,
                        flags = 0x00000001,
                        decodedStartLinear = 0x1000,
                        decodedEndLinear = 0x1010,
                        instructionCount = 1,
                        reachableInstructionCount = 1,
                        reachableByteCount = 1,
                        reachableCodeRanges = new[]
                        {
                            new LEDisassembler.LeReachabilityRangeInfo { startLinear = 0x1000, endLinear = 0x1001 },
                        },
                        dataCandidateRanges = new[]
                        {
                            new LEDisassembler.LeReachabilityRangeInfo { startLinear = 0x1001, endLinear = 0x1010 },
                        }
                    }
                }
            };

            var payload = LeExports.BuildReachabilityExport(map);

            Assert.Equal("test.exe", payload.input);
            Assert.Equal("0x11223344", payload.entry);
            Assert.Equal("func_11223344", payload.entryName);
            Assert.Equal(2, payload.objectCount);

            // Objects sorted by index.
            Assert.NotNull(payload.objects);
            Assert.Equal(1, payload.objects[0].index);
            Assert.Equal("0x00001000", payload.objects[0].baseAddress);
            Assert.Equal(2, payload.objects[1].index);

            // Range formatting.
            Assert.NotNull(payload.objects[0].reachableCode);
            Assert.Equal("0x00001000", payload.objects[0].reachableCode[0].start);
            Assert.Equal("0x00001001", payload.objects[0].reachableCode[0].end);
            Assert.Equal(1, payload.objects[0].reachableCode[0].bytes);
        }
    }
}
