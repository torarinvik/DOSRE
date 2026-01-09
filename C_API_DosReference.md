# MS-DOS C/C++ API Reference Guide  
*(Borland C++, OpenWatcom, Digital Mars compatible)*

This document is a **flat, paste-ready reference index** of MS-DOS–era C/C++ APIs,
grouped by header file.  
It covers **DOS system services, BIOS wrappers, console I/O, file I/O, memory,
interrupts, EMS, TSRs**, and related low-level facilities commonly used in
1990s DOS software and games.

---

## `<dos.h>` — DOS API wrappers (INT 21h)

### Disk / File / Memory (low-level)
- `absread`
- `abswrite`
- `dos_abs_disk_read`
- `dos_abs_disk_write`
- `dos_alloc`
- `_dos_allocmem`
- `dos_calloc`
- `_dos_close`
- `_dos_commit`
- `dos_creat`
- `_dos_creat`
- `_dos_creatnew`
- `_doserrno`
- `_dosexterr`
- `_dos_findfirst`
- `_dos_findnext`
- `dos_free`
- `_dos_freemem`
- `_dos_open`
- `dos_open`
- `_dos_read`
- `_dos_write`
- `_dos_seek`
- `_dos_lock`

### Date / Time / Attributes
- `_dos_getdate`
- `_dos_setdate`
- `_dos_gettime`
- `_dos_settime`
- `_dos_getfileattr`
- `_dos_setfileattr`
- `_dos_getftime`
- `_dos_setftime`

### Disk / Drive
- `_dos_getdrive`
- `_dos_setdrive`
- `_dos_getdiskfree`
- `_getdiskfree`
- `dos_getdiskfreespace`

### Vectors / TSR / Control
- `_dos_getvect`
- `_dos_setvect`
- `_dos_keep`
- `dos_get_ctrl_break`
- `dos_set_ctrl_break`
- `dos_get_verify`
- `dos_set_verify`

---

## `<dos.h>` (part 2) — far memory, ports, DTA, helpers

### DOS calls & interrupt helpers
- `_bdos`
- `bdosptr`
- `bdosx`
- `_intdos`
- `_intdosx`
- `geninterrupt`

### Interrupt control
- `_disable`
- `_enable`
- `_chain_intr`

### Port I/O
- `_inp`, `_inpw`, `_inpl`
- `_outp`, `_outpw`, `_outpl`

### Memory (far / segmented)
- `allocmem`
- `freemem`
- `farcalloc`
- `farmalloc`
- `farrealloc`
- `farfree`
- `farcoreleft`

### Directory / DTA / Disk
- `getcurdir`
- `getdisk`
- `setdisk`
- `getdta`
- `setdta`
- `getpsp`

### File search
- `findfirst`
- `findnext`
- `parsfnm`
- `response_expand`

### Date / Time
- `getdate`
- `gettime`
- `getverify`
- `setverify`
- `getcbrk`
- `setcbrk`

### Pointer / Segment macros
- `_FP_OFF`
- `_FP_SEG`
- `_MK_FP`
- `_segread`
- `peek`
- `peekb`
- `poke`
- `pokeb`

---

## `<int.h>` — Interrupt vector management

- `int_gen`
- `int_getvector`
- `int_setvector`
- `int_intercept`
- `int_restore`
- `int_prev`
- `int_on`
- `int_off`

---

## `<bios.h>` — BIOS interrupt wrappers (INT 10h, 13h, 16h, etc.)

### Disk / Hardware
- `biosdisk`
- `_bios_disk`

### Keyboard
- `bioskey`
- `_bios_keybrd`

### Time / Memory
- `_bios_timeofday`
- `_bios_memsize`
- `biosmemory`

### Printer / Serial
- `_bios_printer`
- `_bios_serialcom`

### Generic interrupt wrappers
- `_int86`
- `_int86x`
- `int86`
- `int86x`

---

## `<conio.h>` — Direct console I/O (text mode)

- `getch`
- `getche`
- `kbhit`
- `putch`
- `cprintf`
- `cscanf`
- `clrscr`
- `gotoxy`
- `wherex`
- `wherey`
- `textcolor`
- `textbackground`
- `window`
- `delline`
- `insline`
- `normvideo`

---

## `<io.h>` — Low-level file I/O (POSIX-like)

- `open`
- `close`
- `read`
- `write`
- `lseek`
- `tell`
- `creat`
- `unlink`
- `access`
- `_access`
- `chmod`
- `_chmod`
- `chsize`
- `_chsize`
- `dup`
- `dup2`
- `eof`
- `filelength`
- `isatty`
- `locking`
- `setmode`
- `sopen`
- `umask`
- `mktemp`

---

## `<direct.h>` — Directory & path utilities

- `_chdir`
- `_chdrive`
- `_getcwd`
- `_getdrive`
- `_mkdir`
- `_rmdir`
- `fnsplit`
- `fnmerge`
- `searchpath`

---

## `<process.h>` — Process & execution control

- `_exec`
- `_execl`
- `_execle`
- `_execlp`
- `_execv`
- `_execve`
- `_execvp`
- `_spawnl`
- `_spawnle`
- `_spawnlp`
- `_spawnv`
- `_spawnve`
- `_spawnvp`
- `_beginthread`
- `_endthread`
- `_getpid`
- `_exit`
- `abort`

---

## `<emm.h>` — Expanded Memory (EMS)

- `emm_allocpages`
- `emm_freepages`
- `emm_map`
- `emm_save_map`
- `emm_restore_map`
- `emm_getversion`
- `emm_gethandlecount`
- `emm_getpageframe`

---

## `<handle.h>` — EMS handle pointers

- `handle_malloc`
- `handle_free`
- `handle_realloc`
- `handle_strdup`
- `handle_ishandle`

---

## `<tsr.h>` — TSR (Terminate-and-Stay-Resident)

- `tsr_install`
- `tsr_uninstall`
- `tsr_service`

---

## `<sound.h>` — PC speaker / simple sound

- `sound`
- `nosound`
- `delay`

---

## `<msmouse.h>` — Microsoft mouse driver

- `mouse_init`
- `mouse_show`
- `mouse_hide`
- `mouse_pos`
- `mouse_pressinfo`
- `mouse_releaseinfo`

---

## `<swap.h>` — Overlay / memory swapping

- `swap_init`
- `swap_term`
- `swap_push`
- `swap_pop`

---

## `<winio.h>` — Direct hardware I/O (protected/extended)

- `inport`
- `outport`
- `inportb`
- `outportb`

---

## Notes

- Function availability varies by **compiler**, **memory model**, and **DOS extender**.
- Borland, OpenWatcom, Digital Mars, and Microsoft C share large overlaps but differ
  in naming (`int86` vs `_int86`, etc.).
- For **absolute completeness**, generate this list automatically from the actual
  compiler headers you are targeting.

---

*End of reference*
