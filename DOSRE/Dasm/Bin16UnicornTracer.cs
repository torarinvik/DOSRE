using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using DOSRE.Unicorn;

namespace DOSRE.Dasm
{
    public static class Bin16UnicornTracer
    {
        public sealed class TraceOptions
        {
            public uint StartAddr { get; set; }
            public uint WindowSize { get; set; } = 0x10000;
            public nuint MaxInstructions { get; set; } = 10_000;

            // Linear base for the code segment (must be < 1MB so CS fits in 16-bit)
            public uint CodeLinearBase { get; set; } = 0x20000;
            public uint StackLinearBase { get; set; } = 0x40000;
        }

        private sealed class TraceContext
        {
            public StringBuilder Sb { get; } = new();
            public Dictionary<uint, string> AsmByAddr { get; }
            public uint StartAddr { get; }
            public uint WindowSize { get; }
            public nuint Max { get; }
            public uint Step;

            public TraceContext(Dictionary<uint, string> asmByAddr, uint startAddr, uint windowSize, nuint max)
            {
                AsmByAddr = asmByAddr;
                StartAddr = startAddr;
                WindowSize = windowSize;
                Max = max;
            }
        }

        public static void TracePromotedAsmToFile(string inAsm, string outTrace, TraceOptions opts)
        {
            if (string.IsNullOrWhiteSpace(inAsm)) throw new ArgumentException("Missing input asm", nameof(inAsm));
            if (!File.Exists(inAsm)) throw new FileNotFoundException("Input asm not found", inAsm);
            if (string.IsNullOrWhiteSpace(outTrace)) throw new ArgumentException("Missing output trace path", nameof(outTrace));
            if (opts == null) throw new ArgumentNullException(nameof(opts));
            if (opts.WindowSize == 0 || opts.WindowSize > 0x10000) throw new ArgumentOutOfRangeException(nameof(opts.WindowSize), "WindowSize must be 1..0x10000");

            var lifted = Bin16AsmLifter.LiftLines(File.ReadAllLines(inAsm), inAsm);
            var nodes = lifted.Nodes.Where(x => x.Kind == "insn" || x.Kind == "db")
                .Where(x => x.Addr.HasValue && !string.IsNullOrWhiteSpace(x.BytesHex))
                .ToList();

            var start = opts.StartAddr;
            var endExclusive = start + opts.WindowSize;

            var bytesByAddr = new Dictionary<uint, byte[]>();
            var asmByAddr = new Dictionary<uint, string>();

            foreach (var n in nodes)
            {
                var a = n.Addr!.Value;
                if (a < start || a >= endExclusive)
                    continue;

                var bytes = ParseHex(n.BytesHex);
                bytesByAddr[a] = bytes;
                asmByAddr[a] = n.Asm ?? string.Empty;
            }

            File.WriteAllText(outTrace, TraceWindow(bytesByAddr, asmByAddr, lifted.StreamSha256, opts));
        }

        private static string TraceWindow(
            Dictionary<uint, byte[]> bytesByAddr,
            Dictionary<uint, string> asmByAddr,
            string streamSha256,
            TraceOptions opts)
        {
            UnicornResolver.Register();

            var ctx = new TraceContext(asmByAddr, opts.StartAddr, opts.WindowSize, opts.MaxInstructions);
            ctx.Sb.AppendLine($"# DOSRE BIN16 Unicorn trace");
            ctx.Sb.AppendLine($"# stream_sha256: {streamSha256}");
            ctx.Sb.AppendLine($"# start: 0x{opts.StartAddr:X8} window: 0x{opts.WindowSize:X} max_insn: {opts.MaxInstructions}");
            ctx.Sb.AppendLine();

            var err = UnicornNative.uc_open(arch: (int)UcArch.X86, mode: (int)UcMode.UC_MODE_16, out var uc);
            if (err != UcErr.OK)
                throw new UnicornException($"uc_open failed: {UnicornNative.StrError(err)}");

            nuint hookCode = 0;
            nuint hookIntr = 0;

            var haveGch = false;
            GCHandle gch = default;
            UnicornNative.HookCode cbCode;
            UnicornNative.HookIntr cbIntr;

            try
            {
                // Map code window (rounded up to 4K pages)
                var codeSize = RoundUpToPage(opts.WindowSize);
                var codeBase = opts.CodeLinearBase;
                err = UnicornNative.uc_mem_map(uc, codeBase, codeSize, (uint)UcProt.ALL);
                if (err != UcErr.OK)
                    throw new UnicornException($"uc_mem_map(code) failed: {UnicornNative.StrError(err)}");

                // Map a simple stack segment.
                var stackSize = RoundUpToPage(0x10000);
                var stackBase = opts.StackLinearBase;
                err = UnicornNative.uc_mem_map(uc, stackBase, stackSize, (uint)UcProt.ALL);
                if (err != UcErr.OK)
                    throw new UnicornException($"uc_mem_map(stack) failed: {UnicornNative.StrError(err)}");

                // Write bytes into the code window.
                foreach (var kv in bytesByAddr.OrderBy(k => k.Key))
                {
                    var logicalAddr = kv.Key;
                    var offset = logicalAddr - opts.StartAddr;
                    if (offset >= opts.WindowSize) continue;
                    var linear = (ulong)codeBase + offset;
                    var b = kv.Value;
                    err = UnicornNative.uc_mem_write(uc, linear, b, (ulong)b.Length);
                    if (err != UcErr.OK)
                        throw new UnicornException($"uc_mem_write failed at 0x{logicalAddr:X8}: {UnicornNative.StrError(err)}");
                }

                // Set segment registers so CS:IP matches our window (CS<<4 == codeBase).
                ulong cs = (ushort)(codeBase >> 4);
                ulong ss = (ushort)(stackBase >> 4);
                ulong ip = (ushort)0;
                ulong sp = (ushort)0xFFFE;

                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_CS, ref cs);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(CS) failed: {UnicornNative.StrError(err)}");
                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_DS, ref cs);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(DS) failed: {UnicornNative.StrError(err)}");
                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_ES, ref cs);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(ES) failed: {UnicornNative.StrError(err)}");

                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_SS, ref ss);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(SS) failed: {UnicornNative.StrError(err)}");

                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_IP, ref ip);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(IP) failed: {UnicornNative.StrError(err)}");

                err = UnicornNative.uc_reg_write(uc, (int)UcX86Reg.UC_X86_REG_SP, ref sp);
                if (err != UcErr.OK) throw new UnicornException($"uc_reg_write(SP) failed: {UnicornNative.StrError(err)}");

                // Hook state via user_data
                gch = GCHandle.Alloc(ctx);
                haveGch = true;
                var userData = GCHandle.ToIntPtr(gch);

                cbCode = (ucHandle, address, size, ud) =>
                {
                    try
                    {
                        var localCtx = (TraceContext)GCHandle.FromIntPtr(ud).Target!;
                        if (localCtx.Step >= localCtx.Max)
                        {
                            UnicornNative.uc_emu_stop(ucHandle);
                            return;
                        }

                        UnicornNative.uc_reg_read(ucHandle, (int)UcX86Reg.UC_X86_REG_CS, out ulong rcs64);
                        UnicornNative.uc_reg_read(ucHandle, (int)UcX86Reg.UC_X86_REG_IP, out ulong rip64);

                        var rcs = (ushort)rcs64;
                        var rip = (ushort)rip64;
                        var logical = localCtx.StartAddr + rip;
                        var maxRead = size == 0 ? 16u : Math.Min(size, 16u);
                        var tmp = new byte[maxRead];
                        var r = UnicornNative.uc_mem_read(ucHandle, address, tmp, maxRead);
                        var bytesHex = r == UcErr.OK ? Convert.ToHexString(tmp).ToLowerInvariant() : "";

                        localCtx.AsmByAddr.TryGetValue(logical, out var asm);
                        asm ??= string.Empty;

                        localCtx.Sb.AppendLine($"{localCtx.Step,6}  {rcs:X4}:{rip:X4}  addr=0x{logical:X8}  size={size}  bytes={bytesHex}  asm={asm}");
                        localCtx.Step++;
                    }
                    catch
                    {
                        // Best-effort tracing; stop on unexpected callback failures.
                        UnicornNative.uc_emu_stop(ucHandle);
                    }
                };

                cbIntr = (ucHandle, intno, ud) =>
                {
                    try
                    {
                        var localCtx = (TraceContext)GCHandle.FromIntPtr(ud).Target!;
                        UnicornNative.uc_reg_read(ucHandle, (int)UcX86Reg.UC_X86_REG_CS, out ulong rcs64);
                        UnicornNative.uc_reg_read(ucHandle, (int)UcX86Reg.UC_X86_REG_IP, out ulong rip64);
                        var rcs = (ushort)rcs64;
                        var rip = (ushort)rip64;
                        var logical = localCtx.StartAddr + rip;
                        localCtx.Sb.AppendLine($"{localCtx.Step,6}  {rcs:X4}:{rip:X4}  addr=0x{logical:X8}  INT 0x{intno:X2}");
                        UnicornNative.uc_emu_stop(ucHandle);
                    }
                    catch
                    {
                        UnicornNative.uc_emu_stop(ucHandle);
                    }
                };

                var fpCode = Marshal.GetFunctionPointerForDelegate(cbCode);
                var fpIntr = Marshal.GetFunctionPointerForDelegate(cbIntr);

                err = UnicornNative.uc_hook_add(uc, out hookIntr, (int)UcHookType.INTR, fpIntr, userData, 1, 0);
                if (err != UcErr.OK)
                    throw new UnicornException($"uc_hook_add(INTR) failed: {UnicornNative.StrError(err)}");

                err = UnicornNative.uc_hook_add(uc, out hookCode, (int)UcHookType.CODE, fpCode, userData, codeBase, codeBase + opts.WindowSize - 1);
                if (err != UcErr.OK)
                    throw new UnicornException($"uc_hook_add(CODE) failed: {UnicornNative.StrError(err)}");

                // Execute.
                var begin = (ulong)codeBase;
                var until = (ulong)(codeBase + opts.WindowSize - 1);
                err = UnicornNative.uc_emu_start(uc, begin, until, timeout: 0, count: opts.MaxInstructions);

                if (err != UcErr.OK)
                    ctx.Sb.AppendLine($"# uc_emu_start error: {UnicornNative.StrError(err)}");
            }
            finally
            {
                if (hookCode != 0) UnicornNative.uc_hook_del(uc, hookCode);
                if (hookIntr != 0) UnicornNative.uc_hook_del(uc, hookIntr);
                if (haveGch && gch.IsAllocated) gch.Free();
                UnicornNative.uc_close(uc);
            }

            return ctx.Sb.ToString();
        }

        private static nuint RoundUpToPage(uint size)
        {
            const uint page = 0x1000;
            var n = (size + page - 1) & ~(page - 1);
            return (nuint)n;
        }

        private static byte[] ParseHex(string hex)
        {
            hex = new string((hex ?? string.Empty).Where(Uri.IsHexDigit).ToArray());
            if (hex.Length % 2 != 0)
                throw new InvalidDataException("Odd-length hex byte string");

            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }
}
