using System;
using System.Runtime.InteropServices;

namespace DOSRE.Unicorn
{
    internal enum UcErr : int
    {
        OK = 0,
    }

    [Flags]
    internal enum UcMode : int
    {
        // From unicorn.h
        UC_MODE_16 = 1 << 1,
    }

    internal enum UcArch : int
    {
        // From unicorn.h
        X86 = 4,
    }

    [Flags]
    internal enum UcProt : int
    {
        NONE = 0,
        READ = 1,
        WRITE = 2,
        EXEC = 4,
        ALL = 7,
    }

    [Flags]
    internal enum UcHookType : int
    {
        // From unicorn.h
        INTR = 1 << 0,
        CODE = 1 << 2,
    }

    internal enum UcX86Reg : int
    {
        // From /opt/homebrew/include/unicorn/x86.h
        UC_X86_REG_INVALID = 0,
        UC_X86_REG_AH = 1,
        UC_X86_REG_AL = 2,
        UC_X86_REG_AX = 3,
        UC_X86_REG_BH = 4,
        UC_X86_REG_BL = 5,
        UC_X86_REG_BP = 6,
        UC_X86_REG_BPL = 7,
        UC_X86_REG_BX = 8,
        UC_X86_REG_CH = 9,
        UC_X86_REG_CL = 10,
        UC_X86_REG_CS = 11,
        UC_X86_REG_CX = 12,
        UC_X86_REG_DH = 13,
        UC_X86_REG_DI = 14,
        UC_X86_REG_DIL = 15,
        UC_X86_REG_DL = 16,
        UC_X86_REG_DS = 17,
        UC_X86_REG_DX = 18,
        UC_X86_REG_EAX = 19,
        UC_X86_REG_EBP = 20,
        UC_X86_REG_EBX = 21,
        UC_X86_REG_ECX = 22,
        UC_X86_REG_EDI = 23,
        UC_X86_REG_EDX = 24,
        UC_X86_REG_EFLAGS = 25,
        UC_X86_REG_EIP = 26,
        // 27 is reserved/unused in header due to explicit ES assignment.
        UC_X86_REG_ES = 28, // UC_X86_REG_EIP + 2
        UC_X86_REG_ESI = 29,
        UC_X86_REG_ESP = 30,
        UC_X86_REG_FPSW = 31,
        UC_X86_REG_FS = 32,
        UC_X86_REG_GS = 33,
        UC_X86_REG_IP = 34,
        UC_X86_REG_RAX = 35,
        // ... (unused)
        UC_X86_REG_SI = 45,
        UC_X86_REG_SIL = 46,
        UC_X86_REG_SP = 47,
        UC_X86_REG_SPL = 48,
        UC_X86_REG_SS = 49,
    }

    internal static class UnicornNative
    {
        internal const string DllName = "unicorn";
        internal const string ShimDllName = "dosre_unicorn_shim";

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void HookCode(IntPtr uc, ulong address, uint size, IntPtr userData);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void HookIntr(IntPtr uc, uint intno, IntPtr userData);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_open(int arch, int mode, out IntPtr uc);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_close(IntPtr uc);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr uc_strerror(UcErr err);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_mem_map(IntPtr uc, ulong address, nuint size, uint perms);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_mem_write(IntPtr uc, ulong address, byte[] bytes, ulong size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_mem_read(IntPtr uc, ulong address, byte[] bytes, ulong size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_reg_write(IntPtr uc, int regid, ref ulong value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_reg_read(IntPtr uc, int regid, out ulong value);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_emu_start(IntPtr uc, ulong begin, ulong until, ulong timeout, nuint count);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_emu_stop(IntPtr uc);

        // NOTE: uc_hook_add is variadic in Unicorn, so we call it via a tiny native shim.
        [DllImport(ShimDllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "dosre_uc_hook_add")]
        internal static extern UcErr uc_hook_add(IntPtr uc, out nuint hh, int type, IntPtr callback, IntPtr userData, ulong begin, ulong end);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UcErr uc_hook_del(IntPtr uc, nuint hh);

        internal static string StrError(UcErr err)
        {
            var p = uc_strerror(err);
            return p == IntPtr.Zero ? err.ToString() : Marshal.PtrToStringAnsi(p) ?? err.ToString();
        }
    }
}
