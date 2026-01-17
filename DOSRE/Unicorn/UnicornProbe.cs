using System;
using System.Runtime.InteropServices;

namespace DOSRE.Unicorn
{
    public static class UnicornProbe
    {
        public static void Run()
        {
            UnicornResolver.Register();

            var err = UnicornNative.uc_open((int)UcArch.X86, (int)UcMode.UC_MODE_16, out var uc);
            Console.WriteLine($"uc_open: {err} ({UnicornNative.StrError(err)})");

            if (err == UcErr.OK && uc != IntPtr.Zero)
            {
                // Minimal emulation (no hooks): map 1 page, write NOP, execute 1 instruction.
                const uint codeBase = 0x20000;
                var mapErr = UnicornNative.uc_mem_map(uc, codeBase, (nuint)0x1000, (uint)UcProt.ALL);
                Console.WriteLine($"uc_mem_map: {mapErr} ({UnicornNative.StrError(mapErr)})");

                if (mapErr == UcErr.OK)
                {
                    var wErr = UnicornNative.uc_mem_write(uc, codeBase, new byte[] { 0x90 }, 1);
                    Console.WriteLine($"uc_mem_write: {wErr} ({UnicornNative.StrError(wErr)})");

                    ulong cs = (ushort)(codeBase >> 4);
                    ulong ip = 0;
                    UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_CS, ref cs);
                    UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_IP, ref ip);

                    // Hook: stop after first CODE callback.
                    nuint hh = 0;
                    UnicornNative.HookCode cb = (ucHandle, address, size, userData) =>
                    {
                        UnicornNative.uc_emu_stop(ucHandle);
                    };
                    var fp = Marshal.GetFunctionPointerForDelegate(cb);
                    var hErr = UnicornNative.uc_hook_add(uc, out hh, (int)UcHookType.CODE, fp, IntPtr.Zero, codeBase, codeBase + 0x10);
                    Console.WriteLine($"uc_hook_add(CODE): {hErr} ({UnicornNative.StrError(hErr)}) hh={hh}");

                    var eErr = UnicornNative.uc_emu_start(uc, codeBase, codeBase + 0x10, timeout: 0, count: 0);
                    Console.WriteLine($"uc_emu_start(hooked): {eErr} ({UnicornNative.StrError(eErr)})");

                    if (hh != 0)
                    {
                        var dErr = UnicornNative.uc_hook_del(uc, hh);
                        Console.WriteLine($"uc_hook_del: {dErr} ({UnicornNative.StrError(dErr)})");
                    }
                }

                var cerr = UnicornNative.uc_close(uc);
                Console.WriteLine($"uc_close: {cerr} ({UnicornNative.StrError(cerr)})");
            }
        }
    }
}
