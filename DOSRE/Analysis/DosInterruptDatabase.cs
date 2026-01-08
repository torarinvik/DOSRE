using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using DOSRE.Enums;
using Newtonsoft.Json.Linq;

namespace DOSRE.Analysis
{
    public sealed class DosInterruptDatabase
    {
        private const string PrimaryResourceName = "DOSRE.Analysis.Assets.DOSINTS_def.json";
        private const string ResourceSuffix = "INTS_def.json";

        // Optional: allow users to drop large interrupt databases locally without embedding/committing them.
        // - If DOSRE_INTS_DIR is set, load *.json from that folder (non-recursive).
        // - Otherwise, if ./DosInterrupts exists, load *.json from there (non-recursive).
        private const string LocalInterruptDirEnvVar = "DOSRE_INTS_DIR";
        private const string DefaultLocalInterruptDirName = "DosInterrupts";

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

        private static EnumToolchainHint _currentToolchainHint = EnumToolchainHint.None;

        public static void SetCurrentToolchainHintGlobal(EnumToolchainHint hint)
        {
            lock (_lock)
            {
                _currentToolchainHint = hint;

                // Rebuild instance so toolchain-specific overlays take effect immediately.
                // (Keep it best-effort: if something fails, fallback to previous instance behavior.)
                _instance = null;
            }
        }

        public static DosInterruptDatabase Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_instance != null)
                        return _instance;

                    var embedded = LoadFromEmbeddedResources();
                    var merged = embedded?._intsByNo != null
                        ? new Dictionary<byte, InterruptEntry>(embedded._intsByNo)
                        : new Dictionary<byte, InterruptEntry>();

                    TryMergeLocalInterruptPacksInto(merged);
                    _instance = new DosInterruptDatabase(merged);
                    return _instance;
                }
            }
        }

        private static void TryMergeLocalInterruptPacksInto(Dictionary<byte, InterruptEntry> dest)
        {
            try
            {
                if (dest == null)
                    return;

                var dir = Environment.GetEnvironmentVariable(LocalInterruptDirEnvVar);
                if (string.IsNullOrWhiteSpace(dir))
                {
                    var cwd = Directory.GetCurrentDirectory();
                    dir = Path.Combine(cwd, DefaultLocalInterruptDirName);
                }

                if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                    return;

                var files = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly)
                    .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var path in files)
                {
                    try
                    {
                        // Toolchain filtering by filename (best-effort).
                        // If the user specifies -watcom/-borland, load generic packs plus the matching toolchain packs.
                        if (!ShouldLoadToolchainSpecificPath(path, _currentToolchainHint))
                            continue;

                        var json = File.ReadAllText(path);
                        var db = Parse(json);
                        if (db == null)
                            continue;
                        MergeInto(dest, db._intsByNo);
                    }
                    catch
                    {
                        // Ignore malformed local packs; keep core DB working.
                    }
                }
            }
            catch
            {
                // Ignore; local packs are best-effort.
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
            return TryDescribe(intNo, ah, ax, (int?)null, out description);
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

            InterruptFunction bestFn = null;
            if (entry.FunctionsByCode != null && ax.HasValue && entry.FunctionsByCode.TryGetValue(ax.Value, out var axList) && axList != null && axList.Count > 0)
            {
                var chosen = ChooseBestFunction(axList, dosVersionInt ?? _currentDosVersionInt);
                bestFn = chosen ?? axList[0];
            }
            else if (entry.FunctionsByCode != null && selValue.HasValue && entry.FunctionsByCode.TryGetValue(selValue.Value, out var selList) && selList != null && selList.Count > 0)
            {
                var chosen = ChooseBestFunction(selList, dosVersionInt ?? _currentDosVersionInt);
                bestFn = chosen ?? selList[0];
            }

            if (bestFn != null)
            {
                // Keep it concise in output; include param hint in parentheses if it fits.
                var baseName = string.IsNullOrEmpty(entry.Name) ? $"INT 0x{intNo:X2}" : entry.Name;
                var fnName = bestFn.Name ?? string.Empty;
                if (string.IsNullOrEmpty(fnName))
                {
                    description = baseName;
                    return true;
                }

                var paramHint = string.Empty;
                if (bestFn.Params != null && bestFn.Params.Length > 0)
                {
                    // Take first param hint only to reduce noise.
                    paramHint = bestFn.Params[0];
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

        private static DosInterruptDatabase LoadFromEmbeddedResources()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();

                // Prefer loading all INTS_def.json resources (base DB + overlays).
                // This enables adding compiler/SDK-specific overlays (e.g., Watcom/Borland) without code changes.
                var names = asm.GetManifestResourceNames()
                    .Where(n => n.EndsWith(ResourceSuffix, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                // Ensure the primary DB is first if present.
                // If a toolchain is selected, skip non-matching toolchain overlays.
                names = names
                    .Where(n => ShouldLoadToolchainSpecificResourceName(n, _currentToolchainHint))
                    .ToList();

                names.Sort((a, b) =>
                {
                    if (string.Equals(a, PrimaryResourceName, StringComparison.OrdinalIgnoreCase)) return -1;
                    if (string.Equals(b, PrimaryResourceName, StringComparison.OrdinalIgnoreCase)) return 1;
                    return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
                });

                if (names.Count == 0)
                {
                    // Backwards compatibility: try the original hard-coded name.
                    names.Add(PrimaryResourceName);
                }

                var merged = new Dictionary<byte, InterruptEntry>();

                foreach (var resName in names)
                {
                    using (var s = asm.GetManifestResourceStream(resName))
                    {
                        if (s == null)
                            continue;
                        using (var sr = new StreamReader(s))
                        {
                            var json = sr.ReadToEnd();
                            var db = Parse(json);
                            if (db == null)
                                continue;
                            MergeInto(merged, db._intsByNo);
                        }
                    }
                }

                return new DosInterruptDatabase(merged);
            }
            catch
            {
                return null;
            }
        }

        private static bool ShouldLoadToolchainSpecificResourceName(string resName, EnumToolchainHint hint)
        {
            if (string.IsNullOrEmpty(resName))
                return true;

            // Convention: toolchain overlays have BORLAND/WATCOM in their resource names.
            var isBorland = resName.IndexOf("BORLAND", StringComparison.OrdinalIgnoreCase) >= 0;
            var isWatcom = resName.IndexOf("WATCOM", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!isBorland && !isWatcom)
                return true;

            if (hint == EnumToolchainHint.None)
                return true;

            if (hint == EnumToolchainHint.Borland)
                return isBorland;
            if (hint == EnumToolchainHint.Watcom)
                return isWatcom;

            return true;
        }

        private static bool ShouldLoadToolchainSpecificPath(string path, EnumToolchainHint hint)
        {
            if (string.IsNullOrEmpty(path))
                return true;

            var file = Path.GetFileName(path) ?? string.Empty;
            var isBorland = file.IndexOf("borland", StringComparison.OrdinalIgnoreCase) >= 0;
            var isWatcom = file.IndexOf("watcom", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!isBorland && !isWatcom)
                return true;

            if (hint == EnumToolchainHint.None)
                return true;

            if (hint == EnumToolchainHint.Borland)
                return isBorland;
            if (hint == EnumToolchainHint.Watcom)
                return isWatcom;

            return true;
        }

        private static void MergeInto(Dictionary<byte, InterruptEntry> dest, Dictionary<byte, InterruptEntry> src)
        {
            if (dest == null || src == null || src.Count == 0)
                return;

            foreach (var kv in src)
            {
                var intNo = kv.Key;
                var srcEntry = kv.Value;
                if (srcEntry == null)
                    continue;

                InterruptEntry destEntry;
                if (!dest.TryGetValue(intNo, out destEntry) || destEntry == null)
                {
                    // Clone-ish: create a new entry instance so we don't accidentally share mutable dictionaries.
                    dest[intNo] = new InterruptEntry
                    {
                        IntNo = srcEntry.IntNo,
                        Name = srcEntry.Name,
                        Selector = srcEntry.Selector,
                        FunctionsByCode = srcEntry.FunctionsByCode != null
                            ? srcEntry.FunctionsByCode.ToDictionary(p => p.Key, p => p.Value?.ToList() ?? new List<InterruptFunction>())
                            : new Dictionary<ushort, List<InterruptFunction>>()
                    };
                    continue;
                }

                // Overlay name/selector if the base is empty.
                if (string.IsNullOrEmpty(destEntry.Name) && !string.IsNullOrEmpty(srcEntry.Name))
                    destEntry.Name = srcEntry.Name;
                if (string.IsNullOrEmpty(destEntry.Selector) && !string.IsNullOrEmpty(srcEntry.Selector))
                    destEntry.Selector = srcEntry.Selector;

                if (srcEntry.FunctionsByCode == null)
                    continue;
                if (destEntry.FunctionsByCode == null)
                    destEntry.FunctionsByCode = new Dictionary<ushort, List<InterruptFunction>>();

                foreach (var fnKv in srcEntry.FunctionsByCode)
                {
                    List<InterruptFunction> destList;
                    if (!destEntry.FunctionsByCode.TryGetValue(fnKv.Key, out destList) || destList == null)
                    {
                        destEntry.FunctionsByCode[fnKv.Key] = fnKv.Value?.ToList() ?? new List<InterruptFunction>();
                        continue;
                    }

                    if (fnKv.Value == null || fnKv.Value.Count == 0)
                        continue;

                    // Append overlay functions (keeps multiple variants for version selection).
                    destList.AddRange(fnKv.Value);
                }
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
