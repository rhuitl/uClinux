
      How to build MPEGDEC Link Library
      ---------------------------------

         (C) Stephane TAVENARD 1997


1) Use a 32 Bit compiler

2) Set some defines:

For Little Endian machines (like Intel CPU) define LITTLE_ENDIAN
In the other case, for Big Endian machines (like Motorola CPU) define
BIG_ENDIAN

In file DEFS.H, you must check the types defintions, ex INT16 should be
a 16 bit integer...
Note: if BOOL is not already defined, define it as an INT16.

You can build 2 sort of MPEG Decoder:

   - Integer math Based (Just define MPEGAUD_INT)
   - Floating point math Based

Note for Motorola 680x0, Integer math decoder is faster than Floating point decoder.
On Intel 80486 or 80586, Floating point math decoder is faster than Integer decoder !!!

3) Compile all files (There are ASM optimized files for 680x0 CPU)
4) Merge them into a library, MPEGDEC.lib

5) You can now use this library with its header MPEGDEC.H


Enjoy Faaast MPEG.
Stephane TAVENARD 1997

Updates for ColdFire:
(15-oct-1999 Rob Scott, rscott@mtrob.fdns.net)

0) The build process has switched from Amiga tools to GNU tools.

1) When using ColdFire development toolchain, please make sure that the
ROOTDIR variable points to the correct location of uCLinux-coldfire.
(Also make sure that you've done a make config in the uClinux tree - required
to get the correct processor defines).

2) In the makefile, there are additional defines: ColdFire, SPLIT_TABLE,
68k_ASM, and ALL_FORMATS. The first one determines coldfire or x86 targets,
and the second one allows the internal MPEG decoder table to fit within the
ColdFire toolchain size constraints. It will be set automatically when 
ColdFire is defined. 68k_ASM enables the assembly language optmizations.
(NOTE: ** the .s files have not been translated to GNU assembler syntax! **)
ALL_FORMATS enables MPEG 1, 2, and 3 decoding, if defined, else only MPEG 3
format is supported.

3) Compile the library via a make command. This will build the library.
	