using System;
using System.Collections.Generic;
using System.IO;

namespace DOSRE.Analysis
{
    public static class UnknownInterruptRecorder
    {
        // Opt-in: set DOSRE_DUMP_UNKNOWN_INTS=1 to write deduplicated unknown int usage lines.
        private const string EnvVar = "DOSRE_DUMP_UNKNOWN_INTS";
        private const string OutputFileName = "dosre.unknown-ints.txt";

        private static readonly object _lock = new object();
        private static readonly HashSet<string> _seen = new HashSet<string>(StringComparer.Ordinal);

        public static void Record(byte intNo, byte? ah, ushort? ax)
        {
            var enabled = Environment.GetEnvironmentVariable(EnvVar);
            if (string.IsNullOrWhiteSpace(enabled) || enabled == "0")
                return;

            var key = $"INT 0x{intNo:X2}";
            if (ah.HasValue)
                key += $" AH=0x{ah.Value:X2}";
            if (ax.HasValue)
                key += $" AX=0x{ax.Value:X4}";

            lock (_lock)
            {
                if (!_seen.Add(key))
                    return;

                try
                {
                    File.AppendAllText(OutputFileName, key + Environment.NewLine);
                }
                catch
                {
                    // Best-effort only.
                }
            }
        }
    }
}
