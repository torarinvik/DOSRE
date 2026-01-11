using System;
using System.Collections.Generic;

namespace DOSRE.Dasm
{
    internal static class LeThunkDiscovery
    {
        internal readonly struct LeObjectSpan
        {
            public readonly int Index;
            public readonly uint BaseAddress;
            public readonly uint VirtualSize;
            public readonly bool IsExecutable;

            public LeObjectSpan(int index, uint baseAddress, uint virtualSize, bool isExecutable)
            {
                Index = index;
                BaseAddress = baseAddress;
                VirtualSize = virtualSize;
                IsExecutable = isExecutable;
            }
        }

        internal sealed class LePointerTableHit
        {
            public uint BaseLinear { get; set; }
            public int EntryCount { get; set; }
        }

        internal static List<LePointerTableHit> ScanPointerTablesForTargets(
            IReadOnlyList<LeObjectSpan> objects,
            Dictionary<int, byte[]> objBytesByIndex,
            Func<uint, bool> isValidTargetLinear,
            HashSet<uint> outTargets,
            int minRunEntries = 6,
            int maxTables = 64,
            int maxEntriesPerTable = 128)
        {
            var hits = new List<LePointerTableHit>();
            if (objects == null || objects.Count == 0 || objBytesByIndex == null || isValidTargetLinear == null || outTargets == null)
                return hits;

            if (minRunEntries < 2)
                minRunEntries = 2;
            if (maxTables <= 0)
                maxTables = 1;
            if (maxEntriesPerTable < minRunEntries)
                maxEntriesPerTable = minRunEntries;

            uint ReadU32(byte[] bytes, int off)
            {
                return unchecked((uint)(bytes[off + 0] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)));
            }

            foreach (var obj in objects)
            {
                if (hits.Count >= maxTables)
                    break;

                if (obj.IsExecutable)
                    continue;

                if (!objBytesByIndex.TryGetValue(obj.Index, out var bytes) || bytes == null || bytes.Length < 8)
                    continue;

                var maxLen = (int)Math.Min(obj.VirtualSize, (uint)bytes.Length);
                if (maxLen < 8)
                    continue;

                var runStartOff = -1;
                var runCount = 0;
                var runTargets = new List<uint>();

                void FlushRun()
                {
                    if (runStartOff >= 0 && runCount >= minRunEntries)
                    {
                        var baseLinear = unchecked(obj.BaseAddress + (uint)runStartOff);
                        hits.Add(new LePointerTableHit { BaseLinear = baseLinear, EntryCount = runCount });
                        foreach (var t in runTargets)
                            outTargets.Add(t);
                    }

                    runStartOff = -1;
                    runCount = 0;
                    runTargets.Clear();
                }

                // Scan 4-byte aligned dword arrays; we only need best-effort.
                for (var off = 0; off + 4 <= maxLen; off += 4)
                {
                    if (hits.Count >= maxTables)
                        break;

                    var val = ReadU32(bytes, off);
                    var ok = val != 0 && isValidTargetLinear(val);

                    if (!ok)
                    {
                        FlushRun();
                        continue;
                    }

                    if (runStartOff < 0)
                        runStartOff = off;

                    if (runCount < maxEntriesPerTable)
                    {
                        runTargets.Add(val);
                        runCount++;
                    }
                    else
                    {
                        // Cap the run to avoid over-collecting; still count it as a hit.
                        FlushRun();
                    }
                }

                FlushRun();
            }

            return hits;
        }
    }
}
