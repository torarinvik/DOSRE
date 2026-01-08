using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpDisasm;
using SharpDisasm.Udis86;
using DOSRE.Analysis;

namespace DOSRE.Dasm
{
    public static partial class MZDisassembler
    {
        private static string TryDecodeInterruptHint(
            Instruction ins,
            byte? lastAh,
            byte? lastAl,
            ushort? lastAxImm,
            ushort? lastBxImm,
            ushort? lastCxImm,
            ushort? lastDxImm,
            ushort? lastSiImm,
            ushort? lastDiImm,
            ushort? lastBpImm,
            ushort? lastDsImm,
            ushort? lastEsImm,
            Dictionary<uint, string> stringSyms,
            Dictionary<uint, string> stringPrev,
            byte[] module)
        {
            var b = ins.Bytes;
            if (b == null || b.Length < 2)
                return string.Empty;

            // int imm8: CD ib
            if (b[0] != 0xCD)
                return string.Empty;

            var intNo = b[1];

            if (intNo == 0x00) return "CPU: Divide By Zero";
            if (intNo == 0x01) return "CPU: Single Step / Trace";
            if (intNo == 0x02) return "CPU: Non-Maskable Interrupt (NMI)";
            if (intNo == 0x03) return "CPU: Breakpoint (INT 3)";
            if (intNo == 0x04) return "CPU: Overflow (INTO)";
            if (intNo == 0x05) return "CPU: Bounds Check / Print Screen";
            if (intNo == 0x06) return "CPU: Invalid Opcode";
            if (intNo == 0x07) return "CPU: Coprocessor Not Available";
            if (intNo == 0x08) return "IRQ0: System Timer Tick";
            if (intNo == 0x09) return "IRQ1: Keyboard String / IRQ9: Redirected IRQ2";

            if (intNo == 0x11) return "BIOS: Get Equipment List ; AX bits: 0=diskette, 1=8087, 4-5=video, 6-7=drives";
            if (intNo == 0x12) return "BIOS: Get Memory Size ; AX=KB (max 640)";
            if (intNo == 0x13) return "BIOS: DISK I/O (CH/CL=cyl/sec, DH/DL=head/drive, ES:BX=buffer)";
            if (intNo == 0x14) return "BIOS: SERIAL I/O (DX=port)";
            if (intNo == 0x15) return "BIOS: SYSTEM SERVICES (Wait/Copy/A20/E820/Joystick)";
            if (intNo == 0x16) return "BIOS: KEYBOARD I/O";
            if (intNo == 0x17) return "BIOS: PRINTER I/O";

            if (intNo == 0x2F) return "MULTIPLEX INTERRUPT (Print/Eject/DPMI/XMS/Cache)";
            if (intNo == 0x31) return "DPMI: DOS Protected Mode Interface";
            if (intNo == 0x33) return "MOUSE DRIVER API";
            if (intNo >= 0x34 && intNo <= 0x3E) return $"Borland Floating Point Emulator (INT {intNo:X2}h)";
            if (intNo >= 0x60 && intNo <= 0x66) return $"Perhaps Game Hook? (User Interrupt INT {intNo:X2}h)";
            if (intNo == 0x67) return "EMS: Expanded Memory (or Perhaps Game Hook?)";
            if (intNo == 0x18) return "BIOS: ROM BASIC";
            if (intNo == 0x19) return "BIOS: Reboot";
            if (intNo == 0x1A) return "BIOS: TIMER & PCI SERVICES (Get Ticks/Set Time/PCI Check)";
            if (intNo == 0x1B) return "BIOS: Ctrl-Break handler";
            if (intNo == 0x1C) return "BIOS: User Timer Tick";

            if (intNo == 0x20) return "DOS: terminate (CP/M style)";
            if (intNo == 0x25) return "DOS: absolute disk read";
            if (intNo == 0x26) return "DOS: absolute disk write";
            if (intNo == 0x27) return "DOS: terminate and stay resident (TSR)";
            if (intNo == 0x24) return "DOS: critical error handler service (internal)";
            if (intNo == 0x29) return "DOS: fast console output (internal)";

            string dbDesc;
            if (DosInterruptDatabase.Instance.TryDescribe(intNo, lastAh, lastAxImm, out dbDesc) && !string.IsNullOrEmpty(dbDesc))
            {
                if (intNo == 0x21 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x01) dbDesc += " ; (returns AL=char)";
                    if (ah == 0x02) { if (lastDxImm.HasValue) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL=char"; }
                    if (ah == 0x05) { if (lastDxImm.HasValue) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL=char"; }
                    if (ah == 0x06) { if (lastDxImm.HasValue && (lastDxImm.Value & 0xFF) != 0xFF) dbDesc += $" ; DL='{(char)(lastDxImm.Value & 0xFF)}'"; dbDesc += " ; DL: FF=input, else=output char"; }

                    if (ah == 0x43)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);

                        if (al == 0x00)
                            dbDesc += " ; returns CX bits: 0x01=RO 0x02=Hidden 0x04=System 0x08=VolLabel 0x10=Dir 0x20=Archive";
                        else if (al == 0x01)
                            dbDesc += " ; CX bits: 0x01=RO 0x02=Hidden 0x04=System 0x08=VolLabel 0x10=Dir 0x20=Archive";
                    }

                    if (ah == 0x0E)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF} ({ (char)('A' + (lastDxImm.Value & 0xFF)) }:)";
                        dbDesc += " ; DL=drive(0=A 1=B)";
                    }

                    if (ah == 0x19)
                    {
                        dbDesc += " ; (returns AL=drive 0=A 1=B)";
                    }

                    if (ah == 0x33)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "Get", 1 => "Set", 5 => "GetBootDrive", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        dbDesc += " ; AL: 0=Get 1=Set 5=BootDrive ; DL=state(0=off 1=on)";
                    }

                    if (ah == 0x36)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF} (0=def 1=A)";
                        dbDesc += " ; DL=drive";
                    }

                    if (ah == 0x39 || ah == 0x3A || ah == 0x3B || ah == 0x3C || ah == 0x3D || ah == 0x41 || ah == 0x43 || ah == 0x4E)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var fn = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(fn)) dbDesc += $" ; path=\"{fn}\"";
                        }
                    }

                    if (ah == 0x3D)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);

                        if (al.HasValue)
                        {
                            var acc = (al.Value & 0x03) switch { 0 => "R", 1 => "W", 2 => "RW", _ => "?" };
                            dbDesc += $" ; AL=0x{al.Value:X2} ({acc})";
                        }
                        dbDesc += " ; AL mode: 0=R 1=W 2=RW, bits 4-6: 0=Comp 1=DAll 2=DW 3=DR 4=DNone";
                    }

                    if (ah == 0x3C)
                    {
                        if (lastCxImm.HasValue)
                        {
                            var attr = lastCxImm.Value;
                            var parts = new List<string>();
                            if ((attr & 0x01) != 0) parts.Add("RO");
                            if ((attr & 0x02) != 0) parts.Add("Hid");
                            if ((attr & 0x04) != 0) parts.Add("Sys");
                            if ((attr & 0x20) != 0) parts.Add("Arch");
                            if (parts.Count > 0) dbDesc += $" ; attr=0x{attr:X} ({string.Join("|", parts)})";
                        }
                    }

                    if (ah == 0x3F || ah == 0x40)
                    {
                        if (lastBxImm.HasValue)
                        {
                            var h = lastBxImm.Value;
                            var hname = h switch { 0 => "stdin", 1 => "stdout", 2 => "stderr", 3 => "stdaux", 4 => "stdprn", _ => $"handle 0x{h:X}" };
                            dbDesc += $" ; { (ah == 0x3F ? "read from" : "write to") } {hname}";
                        }
                        if (lastCxImm.HasValue) dbDesc += $" ; count={lastCxImm.Value}";
                    }

                    if (ah == 0x09)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var s = TryReadDollarString(module, linear, 256);
                            if (!string.IsNullOrEmpty(s)) dbDesc += $" ; \"{s}\"";
                        }
                    }

                    if (ah == 0x25)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; SET INT {lastAl.Value:X2}h HOOK";
                        else if (lastAxImm.HasValue) dbDesc += $" ; SET INT {(byte)(lastAxImm.Value & 0xFF):X2}h HOOK";
                        dbDesc += " ; DS:DX -> new handler";
                    }
                    
                    if (ah == 0x35)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; GET INT {lastAl.Value:X2}h VECTOR";
                        dbDesc += " ; (returns ES:BX -> current handler)";
                    }

                    if (ah == 0x42)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        var origin = al.HasValue ? (al.Value switch { 0 => "START", 1 => "CURR", 2 => "END", _ => $"?({al.Value})" }) : "AL";
                        if (lastBxImm.HasValue) dbDesc += $" ; handle 0x{lastBxImm.Value:X}";
                        if (lastCxImm.HasValue && lastDxImm.HasValue)
                        {
                            long off = ((long)lastCxImm.Value << 16) | lastDxImm.Value;
                            dbDesc += $" ; offset {off} (0x{off:X})";
                        }
                        dbDesc += $" ; origin {origin} (AL={al})";
                    }

                    if (ah == 0x47)
                    {
                        if (lastDxImm.HasValue) dbDesc += $" ; DL={lastDxImm.Value & 0xFF}";
                        dbDesc += " ; DL=drive(0=def 1=A 2=B) DS:SI=64b buffer";
                    }

                    if (ah == 0x48)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value} paragraphs ({lastBxImm.Value * 16} bytes)";
                        dbDesc += " ; BX=paras (returns AX=seg)";
                    }

                    if (ah == 0x4B)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "LoadExec", 1 => "LoadDebug", 3 => "LoadOverlay", 5 => "SetExecState", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }

                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var fn = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(fn)) dbDesc += $" ; path=\"{fn}\"";
                        }

                        if (lastEsImm.HasValue && lastBxImm.HasValue)
                        {
                            var pbLinear = (uint)((lastEsImm.Value << 4) + lastBxImm.Value);
                            if (module != null && pbLinear + 14 <= (uint)module.Length)
                            {
                                var pbOff = (int)pbLinear;
                                var envSeg = ReadUInt16(module, pbOff + 0);
                                var cmdPtr = ReadUInt32(module, pbOff + 2);
                                var cmdOff = (ushort)(cmdPtr & 0xFFFF);
                                var cmdSeg = (ushort)(cmdPtr >> 16);

                                var fcb1Ptr = ReadUInt32(module, pbOff + 6);
                                var fcb1Off = (ushort)(fcb1Ptr & 0xFFFF);
                                var fcb1Seg = (ushort)(fcb1Ptr >> 16);

                                var fcb2Ptr = ReadUInt32(module, pbOff + 10);
                                var fcb2Off = (ushort)(fcb2Ptr & 0xFFFF);
                                var fcb2Seg = (ushort)(fcb2Ptr >> 16);

                                dbDesc += $" ; PB env=0x{envSeg:X4} cmd={cmdSeg:X4}:{cmdOff:X4} fcb1={fcb1Seg:X4}:{fcb1Off:X4} fcb2={fcb2Seg:X4}:{fcb2Off:X4}";

                                var cmdLinear = (uint)((cmdSeg << 4) + cmdOff);
                                var cmd = TryReadDosCommandTail(module, cmdLinear, 126);
                                if (!string.IsNullOrEmpty(cmd)) dbDesc += $" \"{cmd}\"";

                                if (fcb1Ptr != 0)
                                {
                                    var fcb1Linear = (uint)((fcb1Seg << 4) + fcb1Off);
                                    var fcb1 = TryFormatFcbDetail(fcb1Linear, module);
                                    if (!string.IsNullOrEmpty(fcb1)) dbDesc += $" ; {fcb1}";
                                }
                                if (fcb2Ptr != 0)
                                {
                                    var fcb2Linear = (uint)((fcb2Seg << 4) + fcb2Off);
                                    var fcb2 = TryFormatFcbDetail(fcb2Linear, module);
                                    if (!string.IsNullOrEmpty(fcb2)) dbDesc += $" ; {fcb2}";
                                }
                            }
                        }
                        dbDesc += " ; AL: 0=Exec 1=Debug 3=Overlay DS:DX=path ES:BX=params";
                    }

                    if (ah == 0x4A)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value} paragraphs ({lastBxImm.Value * 16} bytes)";
                        dbDesc += " ; ES=seg BX=paras";
                    }

                    if (ah == 0x1A) dbDesc += " ; DS:DX=DTA buffer";

                    if (ah == 0x2A || ah == 0x2B || ah == 0x2C || ah == 0x2D)
                    {
                        var mode = ah switch { 0x2A => "GetDate", 0x2B => "SetDate", 0x2C => "GetTime", 0x2D => "SetTime", _ => "" };
                        dbDesc += $" ; {mode}";
                    }

                    if (ah == 0x30) dbDesc += " ; (returns AL=major AH=minor)";

                    if (ah == 0x4C)
                    {
                        if (lastAl.HasValue) dbDesc += $" ; exit code {lastAl.Value}";
                        dbDesc += " ; AL=exit code";
                    }

                    if (ah == 0x39 || ah == 0x3A || ah == 0x3B)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var p = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(p)) dbDesc += $" ; path=\"{p}\"";
                        }
                        dbDesc += " ; DS:DX=path";
                    }

                    if (ah == 0x4E)
                    {
                        if (lastCxImm.HasValue)
                        {
                            var attr = lastCxImm.Value;
                            var parts = new List<string>();
                            if ((attr & 0x01) != 0) parts.Add("RO");
                            if ((attr & 0x02) != 0) parts.Add("Hid");
                            if ((attr & 0x04) != 0) parts.Add("Sys");
                            if ((attr & 0x08) != 0) parts.Add("Vol");
                            if ((attr & 0x10) != 0) parts.Add("Dir");
                            if ((attr & 0x20) != 0) parts.Add("Arch");
                            var attrStr = parts.Count > 0 ? string.Join("|", parts) : "Norm";
                            dbDesc += $" ; CX=0x{attr:X} ({attrStr})";
                        }
                        dbDesc += " ; CX attr: 1=RO 2=Hid 4=Sys 0x10=Dir 0x20=Arch ; DS:DX=path";
                    }

                    if (ah == 0x4F) dbDesc += " ; (uses current DTA)";

                    if (ah == 0x56)
                    {
                        if (lastDxImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastDxImm.Value) : lastDxImm.Value;
                            var oldp = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(oldp)) dbDesc += $" ; old=\"{oldp}\"";
                        }

                        if (lastEsImm.HasValue && lastDiImm.HasValue)
                        {
                            var linear = (uint)((lastEsImm.Value << 4) + lastDiImm.Value);
                            var newp = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(newp)) dbDesc += $" ; new=\"{newp}\"";
                        }

                        dbDesc += " ; DS:DX=oldpath ES:DI=newpath";
                    }

                    if (ah == 0x57)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue) dbDesc += $" ; {(al.Value == 0 ? "Get" : "Set")}";
                        dbDesc += " ; AL: 0=Get 1=Set ; BX=handle CX=time DX=date";
                    }

                    if (ah == 0x58)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0 => "GetStrat", 1 => "SetStrat", 2 => "GetUMB", 3 => "SetUMB", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        dbDesc += " ; AL: 0=Get 1=Set 2=GetUMB 3=SetUMB";
                    }

                    if (ah == 0x62) dbDesc += " ; (returns BX=PSP segment)";
                    if (ah == 0x34) dbDesc += " ; (returns ES:BX -> In-DOS flag)";
                    if (ah == 0x52) dbDesc += " ; (returns ES:BX -> LoL)";

                    if (ah == 0x6C)
                    {
                        if (lastBxImm.HasValue) dbDesc += $" ; BX=0x{lastBxImm.Value:X} (mode)";
                        if (lastCxImm.HasValue) dbDesc += $" ; CX=0x{lastCxImm.Value:X} (attr)";
                        if (lastDxImm.HasValue) dbDesc += $" ; DX=0x{lastDxImm.Value:X} (action)";

                        if (lastSiImm.HasValue)
                        {
                            var linear = lastDsImm.HasValue ? (uint)((lastDsImm.Value << 4) + lastSiImm.Value) : lastSiImm.Value;
                            var fn = TryReadAsciiString(module, linear, 128);
                            if (!string.IsNullOrEmpty(fn)) dbDesc += $" ; path=\"{fn}\"";
                        }
                        dbDesc += " ; BX=mode CX=attr DX=action DS:SI=path";
                    }

                    if (ah == 0x44)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue)
                            al = (byte)(lastAxImm.Value & 0xFF);
                        
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0x00 => "GetDeviceInfo", 0x01 => "SetDeviceInfo", 0x02 => "Receive(Char)", 0x03 => "Send(Char)", 0x04 => "Receive(Control)", 0x05 => "Send(Control)", 0x06 => "GetInputStat", 0x07 => "GetOutputStat", 0x08 => "IsRemovable", 0x09 => "IsRemoteDrive", 0x0A => "IsRemoteHandle", 0x0B => "SetSharingRetry", 0x0D => "GenericBlockDevice", 0x0E => "GetDriveLogical", 0x0F => "SetDriveLogical", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                        if (lastBxImm.HasValue) dbDesc += $" ; BX={lastBxImm.Value}";
                        dbDesc += " ; AL: 0=Get 1=Set 2=Rd 3=Wr 4=RdCtl 5=WrCtl 6=InStat 7=OutStat 8=Remov";
                    }

                    if (ah == 0x5C)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue) dbDesc += $" ; {(al.Value == 0 ? "Lock" : "Unlock")}";
                        dbDesc += " ; AL: 0=Lock 1=Unlock ; BX=handle CX:DX=offset SI:DI=length";
                    }

                    if (ah == 0x5D)
                    {
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        if (al.HasValue)
                        {
                            var sub = al.Value switch { 0x00 => "ServerDosError", 0x06 => "GetAddressOfPSP", 0x0A => "SetExtendedError", _ => $"sub=0x{al.Value:X2}" };
                            dbDesc += $" ; {sub}";
                        }
                    }

                    if (ah == 0x5E || ah == 0x5F) dbDesc += " ; Network/Redirection Service";

                    if (ah == 0x0F || ah == 0x10 || ah == 0x11 || ah == 0x12 || ah == 0x13 || ah == 0x16 || ah == 0x17 || ah == 0x21 || ah == 0x22 || ah == 0x23 || ah == 0x24 || ah == 0x27 || ah == 0x28)
                    {
                        var fcDetail = TryFormatFcbDetail(lastDxImm, module);
                        if (!string.IsNullOrEmpty(fcDetail)) return dbDesc + " ; " + fcDetail;
                    }

                    if (ah == 0x09 || ah == 0x0A || ah == 0x1A || ah == 0x39 || ah == 0x3A || ah == 0x3B || ah == 0x3C || ah == 0x3D || ah == 0x3F || ah == 0x40 || ah == 0x41 || ah == 0x43 || ah == 0x4B || ah == 0x4E || ah == 0x56 || ah == 0x5A || ah == 0x5B)
                    {
                        var dxDetail = TryFormatPointerDetail(lastDxImm, lastDsImm, "DX", stringSyms, stringPrev);
                        if (!string.IsNullOrEmpty(dxDetail)) return dbDesc + " ; " + dxDetail;
                    }
                    if (ah == 0x47 || ah == 0x6C || ah == 0x71)
                    {
                        var siDetail = TryFormatPointerDetail(lastSiImm, lastDsImm, "SI", stringSyms, stringPrev);
                        if (!string.IsNullOrEmpty(siDetail)) return dbDesc + " ; " + siDetail;
                    }
                }

                if (intNo == 0x10 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x00)
                    {
                        var al = lastAl ?? (byte)(lastAxImm ?? 0);
                        var mode = al switch { 0x03 => "80x25 Text", 0x04 => "320x200 4-color", 0x06 => "640x200 BW", 0x0D => "320x200 16-color (EGA)", 0x0E => "640x200 16-color (EGA)", 0x10 => "640x350 16-color (EGA)", 0x12 => "640x480 16-color (VGA)", 0x13 => "320x200 256-color (VGA)", _ => $"mode 0x{al:X2}" };
                        dbDesc += $" ; {mode}";
                    }
                    else if (ah == 0x01) { if (lastCxImm.HasValue) dbDesc += $" ; shape=0x{lastCxImm.Value:X4} (CH=start CL=end)"; dbDesc += " ; CH=start CL=end"; }
                    else if (ah == 0x02) { if (lastDxImm.HasValue) dbDesc += $" ; row={lastDxImm.Value >> 8} col={lastDxImm.Value & 0xFF}"; dbDesc += " ; BH=page DH=row DL=col"; }
                    else if (ah == 0x03) dbDesc += " ; BH=page (returns CX=shape DX=pos)";
                    else if (ah == 0x06 || ah == 0x07) { if (lastAl.HasValue) dbDesc += $" ; lines={lastAl.Value}"; dbDesc += " ; AL=lines BH=attr CH,CL=top left DH,DL=bottom right"; }
                    else if (ah == 0x08) dbDesc += " ; BH=page (returns AL=char AH=attr)";
                    else if (ah == 0x09 || ah == 0x0A) { if (lastAxImm.HasValue) dbDesc += $" ; char='{(char)(lastAxImm.Value & 0xFF)}'"; dbDesc += " ; AL=char BH=page BL=attr CX=count"; }
                    else if (ah == 0x0C) { if (lastAl.HasValue) dbDesc += $" ; color={lastAl.Value}"; dbDesc += " ; AL=color BH=page CX=x DX=y"; }
                    else if (ah == 0x0D) dbDesc += " ; BH=page CX=x DX=y (returns AL=color)";
                    else if (ah == 0x0F) dbDesc += " ; (returns AL=mode AH=cols BH=page)";
                    else if (ah == 0x13) { if (lastEsImm.HasValue && lastBpImm.HasValue && lastCxImm.HasValue) { var linear = (uint)((lastEsImm.Value << 4) + lastBpImm.Value); var s = TryReadAsciiStringFixed(module, linear, Math.Min((int)lastCxImm.Value, 256)); if (!string.IsNullOrEmpty(s)) dbDesc += $" ; \"{s}\""; } dbDesc += " ; AL=mode BH=page BL=attr CX=len DX=row/col ES:BP=string"; }
                    else if (ah == 0x11) { byte? al = lastAl; if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF); if (al.HasValue) { var sub = DescribeInt10CharacterGeneratorSubfunction(al.Value); dbDesc += $" ; Character generator: {sub}"; } else dbDesc += " ; Character generator"; dbDesc += " ; AL=sub"; }
                    else if (ah == 0x1A) { byte? al = lastAl; if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF); if (al == 0x00) dbDesc += " ; Get Display Combination Code"; else if (al == 0x01) dbDesc += " ; Set Display Combination Code"; else if (al.HasValue) dbDesc += $" ; sub=0x{al.Value:X2}"; dbDesc += " ; AL=sub (returns BL=active display, BH=alternate?)"; }
                    else if (ah == 0x12) { byte? bl = lastBxImm.HasValue ? (byte?)(lastBxImm.Value & 0xFF) : null; if (bl == 0x10) dbDesc += " ; EGA/VGA: Get Configuration"; else if (bl.HasValue) dbDesc += $" ; EGA/VGA: sub=0x{bl.Value:X2}"; dbDesc += " ; BL=sub"; }
                }

                if (intNo == 0x13 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x02 || ah == 0x03)
                    {
                        var op = ah == 0x02 ? "Read" : "Write";
                        byte? al = lastAl;
                        if (!al.HasValue && lastAxImm.HasValue) al = (byte)(lastAxImm.Value & 0xFF);
                        var count = al.HasValue ? al.Value.ToString() : "?";
                        string chs = "";
                        if (lastCxImm.HasValue) { var cx = lastCxImm.Value; var cyl = (cx >> 8) | ((cx & 0xC0) << 2); var sect = cx & 0x3F; chs += $" cyl:{cyl} sect:{sect}"; }
                        if (lastDxImm.HasValue) { var dx = lastDxImm.Value; var head = dx >> 8; var drive = dx & 0xFF; var driveStr = drive >= 0x80 ? $"HDD:{drive:X2}h" : $"FDD:{drive:X2}h"; chs += $" head:{head} {driveStr}"; }
                        dbDesc += $" ; {op} {count} sect{chs}";
                    }
                    else if (ah == 0x00) dbDesc += " ; Reset disk system";
                    else if (ah == 0x01) dbDesc += " ; Get last disk status";
                    else if (ah == 0x08) dbDesc += " ; Get drive parameters";
                }

                if (intNo == 0x14) dbDesc += " ; AH=0:Init AH=1:Send AH=2:Recv AH=3:Status ; DX=port";

                if (intNo == 0x15 && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x86) dbDesc += " ; Wait (CX:DX=microseconds)";
                    else if (ah == 0x87) dbDesc += " ; Move Extended Block (CX=words ES:SI=GDT)";
                    else if (ah == 0x88) dbDesc += " ; Get Extended Memory Size";
                    else if (ah == 0xC0) dbDesc += " ; Get System Config (returns ES:BX -> table)";
                    else if (lastAxImm == 0xE801) dbDesc += " ; Get Ext Memory (AX=1-16MB BX=>16MB)";
                    else if (lastAxImm == 0xE820) dbDesc += " ; Get Memory Map (EAX=E820 EDX=SMAP ES:DI=buf)";
                    else if (lastAxImm == 0x5300) dbDesc += " ; APM: Check Presence";
                }

                if (intNo == 0x16) dbDesc += " ; AH=0:Get AH=1:Peek AH=2:ShiftFlags";
                if (intNo == 0x17) dbDesc += " ; AH=0:Print AH=1:Init AH=2:Status ; DX=port";
                if (intNo == 0x1A) dbDesc += " ; AH=0:GetTicks AH=1:SetTicks AH=2:GetTime AH=4:GetDate";

                if (intNo == 0x2F && lastAh.HasValue)
                {
                    var ah = lastAh.Value;
                    if (ah == 0x15) { var al = lastAl ?? (byte)(lastAxImm ?? 0); var sub = al switch { 0x00 => "CheckPresence", 0x0B => "GetDriveList", 0x0C => "GetVersion", 0x10 => "GetDeviceInfo", _ => $"MSCDEX sub=0x{al:X2}" }; dbDesc += $" ; {sub}"; }
                    else if (lastAxImm.HasValue)
                    {
                        var ax = lastAxImm.Value;
                        if (ax == 0x1680) dbDesc += " ; DPMI: release time slice";
                        else if (ax == 0x1687) dbDesc += " ; DPMI: get entry point";
                        else if (ax == 0x1689) dbDesc += " ; DPMI: get version";
                        else if (ax == 0x4300) dbDesc += " ; XMS: check presence";
                        else if (ax == 0x4310) dbDesc += " ; XMS: get entry point";
                        else if (ah == 0x11) dbDesc += " ; Network: redirector (AL=func)";
                        else if (ah == 0x12) dbDesc += " ; DOS: internal services (AL=func)";
                        else if (ax == 0x1600) dbDesc += " ; Windows: check presence (enhanced mode)";
                        else if (ax == 0x4A11) dbDesc += " ; DoubleSpace: check presence";
                    }
                }

                if (intNo == 0x31 && lastAxImm.HasValue)
                {
                    var ax = lastAxImm.Value;
                    if (ax == 0x0100) dbDesc += $" ; BX={lastBxImm}p ({lastBxImm * 16}b)";
                    if (ax == 0x0501) dbDesc += $" ; size={((uint)(lastBxImm ?? 0) << 16) | (lastCxImm ?? 0)}b";
                }

                if (intNo == 0x33 && lastAxImm.HasValue)
                {
                    var ax = lastAxImm.Value;
                    if (ax == 0x0004) dbDesc += $" ; X={lastCxImm} Y={lastDxImm}";
                }

                return dbDesc;
            }

            UnknownInterruptRecorder.Record(intNo, lastAh, null);
            return $"INT 0x{intNo:X2}";
        }

        private static string DescribeInt10CharacterGeneratorSubfunction(byte al)
        {
            return al switch
            {
                0x00 => "User character load",
                0x01 => "Load ROM BIOS 8x14 monochrome set",
                0x02 => "Load ROM BIOS 8x8 double-dot set",
                0x03 => "Set displayed definition table",
                0x04 => "Load ROM BIOS 8x16 character set",
                0x10 => "User-specified character definition table",
                0x11 => "Load ROM BIOS 8x14 monochrome character set",
                0x12 => "Load ROM 8x8 double-dot character definitions",
                0x14 => "Load ROM 8x16 double-dot character definitions",
                0x20 => "Get pointer to graphics character table for INT 1F (8x8)",
                0x21 => "Set user graphics character pointer at INT 43",
                0x22 => "Load ROM 8x14 character set",
                0x23 => "Load ROM 8x8 double-dot character set",
                0x24 => "Load ROM 8x16 character set",
                0x30 => "Get current character generator information",
                _ => $"sub=0x{al:X2}"
            };
        }
    }
}
