# Makefile for Open Watcom wmake (HELLO.EXE Reconstruction)

# Toolchain definitions
CC = wcc386
LN = wlink
SYSTEM = dos4g

# Compiler flags
# -zastd=c99: Support C99 features
# -6r: Optimize for Pentium (32-bit registers)
# -s: Disable stack checks
# -zq: Quiet mode
CFLAGS = -zastd=c99 -6r -s -zq

# Executable name
TARGET = blst.exe

# List of object files
OBJS = main.obj bdata.obj &
       b0.obj b1.obj b2.obj b3.obj b4.obj b5.obj b6.obj b7.obj b8.obj b9.obj

# Default target
all : $(TARGET)

# Linking rule
$(TARGET) : $(OBJS) .SYMBOLIC
    $(LN) name blst system $(SYSTEM) option quiet option stack=0x8000 option start=_cstart_ &
       libpath C:\WATCOM\LIB386 &
       libpath C:\WATCOM\LIB386\DOS &
       file {$(OBJS)}

# Inference rule for .c to .obj
.c.obj :
    $(CC) $(CFLAGS) $[* -fo=$^@

# Clean rule
clean : .SYMBOLIC
    @if exist *.obj del *.obj
    @if exist $(TARGET) del $(TARGET)
    @if exist *.err del *.err
