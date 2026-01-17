using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace DOSRE.Unicorn
{
    internal static class UnicornResolver
    {
        private static int _registered;

        public static void Register()
        {
            if (Interlocked.Exchange(ref _registered, 1) != 0)
                return;

            NativeLibrary.SetDllImportResolver(typeof(UnicornResolver).Assembly, Resolve);
        }

        private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            if (!string.Equals(libraryName, UnicornNative.DllName, StringComparison.Ordinal))
                return IntPtr.Zero;

            // Prefer explicit Homebrew paths on macOS, but fall back to default loader search.
            var candidates = new[]
            {
                "/opt/homebrew/lib/libunicorn.dylib",
                "/usr/local/lib/libunicorn.dylib",
                "libunicorn.dylib",
                "unicorn",
            };

            foreach (var c in candidates)
            {
                if (NativeLibrary.TryLoad(c, out var handle))
                    return handle;
            }

            return IntPtr.Zero;
        }
    }
}
