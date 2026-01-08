using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json.Linq;

namespace MBBSDASM.Analysis
{
    public sealed class DosInterruptDatabase
    {
        private const string ResourceName = "MBBSDASM.Analysis.Assets.DOSINTS_def.json";

        private readonly Dictionary<byte, InterruptEntry> _intsByNo;

        // Default to a common "90s DOS" baseline (MS-DOS 6.22).
        // This is only used to choose between version-variant entries in the DB.
        private int _currentDosVersionInt = ToVersionInt(6, 22, 0);

        private DosInterruptDatabase(Dictionary<byte, InterruptEntry> intsByNo)
        {
            _intsByNo = intsByNo ?? new Dictionary<byte, InterruptEntry>();
        }

        private static readonly object _lock = new object();
        private static DosInterruptDatabase _instance;

        public static DosInterruptDatabase Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_instance != null)
                        return _instance;
                    _instance = LoadFromEmbeddedResource() ?? new DosInterruptDatabase(new Dictionary<byte, InterruptEntry>());
                    return _instance;
                }
            }
        }

        public void SetCurrentDosVersion(string version)
        {
            var v = ParseVersion(version);
            if (v.HasValue)
                _currentDosVersionInt = v.Value;
        }

        public static void SetCurrentDosVersionGlobal(string version)
        {
            Instance.SetCurrentDosVersion(version);
        }

        public bool TryDescribe(byte intNo, byte? ah, ushort? ax, out string description)
        {
            return TryDescribe(intNo, ah, ax, null, out description);
        }

        public bool TryDescribe(byte intNo, byte? ah, ushort? ax, string dosVersion, out string description)
        {
            var v = ParseVersion(dosVersion);
            return TryDescribe(intNo, ah, ax, v, out description);
        }

        private bool TryDescribe(byte intNo, byte? ah, ushort? ax, int? dosVersionInt, out string description)
        {
            description = string.Empty;

            InterruptEntry entry;
            if (!_intsByNo.TryGetValue(intNo, out entry) || entry == null)
                return false;

            // If no selector, just return base name.
            if (string.IsNullOrEmpty(entry.Selector))
            {
                description = string.IsNullOrEmpty(entry.Name) ? string.Empty : entry.Name;
                return !string.IsNullOrEmpty(description);
            }

            var selector = entry.Selector.Trim().ToUpperInvariant();
            ushort? selValue = null;
            if (selector == "AH")
            {
                if (!ah.HasValue)
                {
                    description = string.IsNullOrEmpty(entry.Name) ? string.Empty : entry.Name;
                    return !string.IsNullOrEmpty(description);
                }
                selValue = ah.Value;
            }
            else if (selector == "AX")
            {
                if (!ax.HasValue)
                {
                    description = string.IsNullOrEmpty(entry.Name) ? string.Empty : entry.Name;
                    return !string.IsNullOrEmpty(description);
                }
                selValue = ax.Value;
            }
            else
            {
                description = string.IsNullOrEmpty(entry.Name) ? string.Empty : entry.Name;
                return !string.IsNullOrEmpty(description);
            }

            if (!selValue.HasValue)
                return false;

            List<InterruptFunction> fnList;
            if (entry.FunctionsByCode != null && entry.FunctionsByCode.TryGetValue(selValue.Value, out fnList) && fnList != null && fnList.Count > 0)
            {
                var chosen = ChooseBestFunction(fnList, dosVersionInt ?? _currentDosVersionInt);
                var fn = chosen ?? fnList[0];

                // Keep it concise in output; include param hint in parentheses if it fits.
                var baseName = string.IsNullOrEmpty(entry.Name) ? $"INT 0x{intNo:X2}" : entry.Name;
                var fnName = fn.Name ?? string.Empty;
                if (string.IsNullOrEmpty(fnName))
                {
                    description = baseName;
                    return true;
                }

                var paramHint = string.Empty;
                if (fn.Params != null && fn.Params.Length > 0)
                {
                    // Take first param hint only to reduce noise.
                    paramHint = fn.Params[0];
                }

                if (!string.IsNullOrEmpty(paramHint))
                    description = baseName + ": " + fnName + " (" + paramHint + ")";
                else
                    description = baseName + ": " + fnName;

                return true;
            }

            // Unknown subfunction: still return base name + selector.
            var selStr = selector == "AH" ? (ah.HasValue ? $"AH=0x{ah.Value:X2}" : "AH=?") : (ax.HasValue ? $"AX=0x{ax.Value:X4}" : "AX=?");
            description = (string.IsNullOrEmpty(entry.Name) ? $"INT 0x{intNo:X2}" : entry.Name) + " (" + selStr + ")";
            return true;
        }

        private static InterruptFunction ChooseBestFunction(List<InterruptFunction> fns, int dosVersionInt)
        {
            if (fns == null || fns.Count == 0)
                return null;

            // Prefer functions whose version range contains the requested version.
            // If multiple match, pick the one with the highest Since (most specific/newest).
            InterruptFunction best = null;
            foreach (var fn in fns)
            {
                if (fn == null)
                    continue;

                if (!VersionInRange(dosVersionInt, fn.SinceVersionInt, fn.UntilVersionInt))
                    continue;

                if (best == null)
                {
                    best = fn;
                    continue;
                }

                var bestSince = best.SinceVersionInt ?? 0;
                var fnSince = fn.SinceVersionInt ?? 0;
                if (fnSince >= bestSince)
                    best = fn;
            }

            return best;
        }

        private static bool VersionInRange(int v, int? since, int? until)
        {
            if (since.HasValue && v < since.Value)
                return false;
            if (until.HasValue && v > until.Value)
                return false;
            return true;
        }

        private static DosInterruptDatabase LoadFromEmbeddedResource()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                using (var s = asm.GetManifestResourceStream(ResourceName))
                {
                    if (s == null)
                        return null;
                    using (var sr = new StreamReader(s))
                    {
                        var json = sr.ReadToEnd();
                        return Parse(json);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private static DosInterruptDatabase Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return null;

            var root = JObject.Parse(json);
            var arr = root["interrupts"] as JArray;
            if (arr == null)
                return null;

            var dict = new Dictionary<byte, InterruptEntry>();
            foreach (var jt in arr)
            {
                var o = jt as JObject;
                if (o == null)
                    continue;

                var intNo = ParseByte(o["int"]);
                if (!intNo.HasValue)
                    continue;

                var entry = new InterruptEntry
                {
                    IntNo = intNo.Value,
                    Name = (string)o["name"] ?? string.Empty,
                    Selector = (string)o["selector"] ?? string.Empty,
                    FunctionsByCode = new Dictionary<ushort, List<InterruptFunction>>()
                };

                var fns = o["functions"] as JArray;
                if (fns != null)
                {
                    foreach (var jfn in fns)
                    {
                        var fo = jfn as JObject;
                        if (fo == null)
                            continue;

                        var code = ParseUShort(fo["code"]);
                        if (!code.HasValue)
                            continue;

                        var fn = new InterruptFunction
                        {
                            Code = code.Value,
                            Name = (string)fo["name"] ?? string.Empty,
                            Params = (fo["params"] as JArray)?.Select(x => (string)x ?? string.Empty).Where(x => !string.IsNullOrEmpty(x)).ToArray() ?? new string[0],
                            Returns = (fo["returns"] as JArray)?.Select(x => (string)x ?? string.Empty).Where(x => !string.IsNullOrEmpty(x)).ToArray() ?? new string[0],
                            SinceVersionInt = ParseVersion(fo["since"]),
                            UntilVersionInt = ParseVersion(fo["until"])
                        };

                        List<InterruptFunction> list;
                        if (!entry.FunctionsByCode.TryGetValue(code.Value, out list) || list == null)
                        {
                            list = new List<InterruptFunction>();
                            entry.FunctionsByCode[code.Value] = list;
                        }
                        list.Add(fn);
                    }
                }

                dict[entry.IntNo] = entry;
            }

            return new DosInterruptDatabase(dict);
        }

        private static byte? ParseByte(JToken token)
        {
            if (token == null)
                return null;

            if (token.Type == JTokenType.Integer)
                return (byte)token.Value<int>();

            var s = (string)token;
            if (string.IsNullOrWhiteSpace(s))
                return null;

            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);

            int v;
            if (int.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out v))
                return (byte)v;

            if (int.TryParse(s, out v))
                return (byte)v;

            return null;
        }

        private static ushort? ParseUShort(JToken token)
        {
            if (token == null)
                return null;

            if (token.Type == JTokenType.Integer)
                return (ushort)token.Value<int>();

            var s = (string)token;
            if (string.IsNullOrWhiteSpace(s))
                return null;

            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s.Substring(2);

            int v;
            if (int.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out v))
                return (ushort)v;

            if (int.TryParse(s, out v))
                return (ushort)v;

            return null;
        }

        private sealed class InterruptEntry
        {
            public byte IntNo;
            public string Name;
            public string Selector;
            public Dictionary<ushort, List<InterruptFunction>> FunctionsByCode;
        }

        private sealed class InterruptFunction
        {
            public ushort Code;
            public string Name;
            public string[] Params;
            public string[] Returns;
            public int? SinceVersionInt;
            public int? UntilVersionInt;
        }

        private static int? ParseVersion(JToken token)
        {
            if (token == null)
                return null;
            var s = (string)token;
            return ParseVersion(s);
        }

        private static int? ParseVersion(string version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return null;

            version = version.Trim();
            var parts = version.Split(new[] { '.', '_' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                return null;

            int major;
            if (!int.TryParse(parts[0], out major))
                return null;

            var minor = 0;
            var patch = 0;
            if (parts.Length >= 2)
                int.TryParse(parts[1], out minor);
            if (parts.Length >= 3)
                int.TryParse(parts[2], out patch);

            return ToVersionInt(major, minor, patch);
        }

        private static int ToVersionInt(int major, int minor, int patch)
        {
            // major.mm.pp -> major*10000 + minor*100 + patch
            return major * 10000 + minor * 100 + patch;
        }
    }
}
