using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        /// <summary>
        /// Best-effort demangler for Watcom C++ symbols.
        /// Watcom mangling typically starts with '?' or 'W?'.
        /// Examples: 
        ///   ?MyFunc$qipv -> MyFunc(int*, void)
        ///   ?MyValue$i   -> int MyValue
        /// </summary>
        public static string DemangleWatcom(string mangled)
        {
            if (string.IsNullOrEmpty(mangled)) return mangled;
            if (!mangled.StartsWith("?") && !mangled.StartsWith("W?")) return mangled;

            try
            {
                // Remove prefix
                string working = mangled.StartsWith("W?") ? mangled.Substring(2) : mangled.Substring(1);

                // Split name and signature
                int dollarIdx = working.IndexOf('$');
                if (dollarIdx == -1) return working;

                string name = working.Substring(0, dollarIdx);
                string signature = working.Substring(dollarIdx + 1);

                if (signature.StartsWith("q"))
                {
                    // Function signature
                    var args = ParseWatcomArgs(signature.Substring(1));
                    return $"{name}({string.Join(", ", args)})";
                }
                else
                {
                    // Variable or simple type
                    var type = ParseWatcomType(ref signature);
                    return $"{type} {name}";
                }
            }
            catch
            {
                // Fallback to original mangled name if parsing fails
                return mangled;
            }
        }

        private static List<string> ParseWatcomArgs(string signature)
        {
            var args = new List<string>();
            string working = signature;
            while (working.Length > 0)
            {
                var type = ParseWatcomType(ref working);
                if (string.IsNullOrEmpty(type)) break;
                args.Add(type);
            }
            return args;
        }

        private static string ParseWatcomType(ref string signature)
        {
            if (signature.Length == 0) return string.Empty;

            bool isUnsigned = false;
            bool isConst = false;
            bool isVolatile = false;

            while (signature.Length > 0)
            {
                if (signature.StartsWith("u"))
                {
                    isUnsigned = true;
                    signature = signature.Substring(1);
                }
                else if (signature.StartsWith("x"))
                {
                    isConst = true;
                    signature = signature.Substring(1);
                }
                else if (signature.StartsWith("y"))
                {
                    isVolatile = true;
                    signature = signature.Substring(1);
                }
                else break;
            }

            if (signature.Length == 0)
            {
                string res = isUnsigned ? "unsigned" : "";
                if (isConst) res = (res + " const").Trim();
                if (isVolatile) res = (res + " volatile").Trim();
                return res;
            }

            char c = signature[0];
            signature = signature.Substring(1);

            string baseType = c switch
            {
                'v' => "void",
                'c' => "char",
                's' => "short",
                'i' => "int",
                'l' => "long",
                'f' => "float",
                'd' => "double",
                'w' => "wchar_t",
                'p' => ParseWatcomType(ref signature) + "*",
                'r' => ParseWatcomType(ref signature) + "&",
                'R' => ParseWatcomType(ref signature) + "&",
                'j' => "long long",
                'k' => "unsigned long long",
                _ => "unknown"
            };

            if (isUnsigned) baseType = "unsigned " + baseType;
            if (isConst) baseType = baseType + " const";
            if (isVolatile) baseType = baseType + " volatile";

            return baseType;
        }
    }
}
