using System;
using System.Collections.Generic;
using DOSRE.Dasm;
using Xunit;

namespace DOSRE.Tests
{
    public class LeThunkDiscoveryTests
    {
        [Fact]
        public void ScanPointerTablesForTargets_FindsRunsInDataObjects()
        {
            // Code object starts at 0x1000; pretend we only accept these exact instruction starts.
            var valid = new HashSet<uint> { 0x00001010, 0x00001020, 0x00001030, 0x00001040, 0x00001050, 0x00001060 };

            bool IsValid(uint addr) => valid.Contains(addr);

            var objects = new List<LeThunkDiscovery.LeObjectSpan>
            {
                new LeThunkDiscovery.LeObjectSpan(index: 1, baseAddress: 0x00001000, virtualSize: 0x100, isExecutable: true),
                new LeThunkDiscovery.LeObjectSpan(index: 2, baseAddress: 0x00002000, virtualSize: 0x40, isExecutable: false)
            };

            // Data object contains 6 consecutive pointers (minRunEntries default is 6).
            var data = new List<byte>();
            void AddU32(uint v)
            {
                data.Add((byte)(v & 0xFF));
                data.Add((byte)((v >> 8) & 0xFF));
                data.Add((byte)((v >> 16) & 0xFF));
                data.Add((byte)((v >> 24) & 0xFF));
            }

            AddU32(0x00001010);
            AddU32(0x00001020);
            AddU32(0x00001030);
            AddU32(0x00001040);
            AddU32(0x00001050);
            AddU32(0x00001060);

            var objBytesByIndex = new Dictionary<int, byte[]> { [2] = data.ToArray() };

            var targets = new HashSet<uint>();
            var hits = LeThunkDiscovery.ScanPointerTablesForTargets(objects, objBytesByIndex, IsValid, targets);

            Assert.Single(hits);
            Assert.Equal(0x00002000u, hits[0].BaseLinear);
            Assert.Equal(6, hits[0].EntryCount);

            Assert.Equal(valid.Count, targets.Count);
            Assert.All(valid, a => Assert.Contains(a, targets));
        }

        [Fact]
        public void ScanPointerTablesForTargets_DoesNotTriggerOnShortRuns()
        {
            var objects = new List<LeThunkDiscovery.LeObjectSpan>
            {
                new LeThunkDiscovery.LeObjectSpan(index: 2, baseAddress: 0x00002000, virtualSize: 0x40, isExecutable: false)
            };

            var bytes = new byte[5 * 4];
            for (var i = 0; i < 5; i++)
            {
                var v = 0x00001000u + (uint)(i * 0x10);
                bytes[i * 4 + 0] = (byte)(v & 0xFF);
                bytes[i * 4 + 1] = (byte)((v >> 8) & 0xFF);
                bytes[i * 4 + 2] = (byte)((v >> 16) & 0xFF);
                bytes[i * 4 + 3] = (byte)((v >> 24) & 0xFF);
            }

            var objBytesByIndex = new Dictionary<int, byte[]> { [2] = bytes };

            var targets = new HashSet<uint>();
            var hits = LeThunkDiscovery.ScanPointerTablesForTargets(objects, objBytesByIndex, _ => true, targets, minRunEntries: 6);

            Assert.Empty(hits);
            Assert.Empty(targets);
        }
    }
}
