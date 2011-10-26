PROG=../../../bin/Codecs/Rar29.so

LOCAL_FLAGS=-DSILENT -DNOCRYPT -DNOVOLUME

MY_WINDOWS=

include ../../../makefile.machine

LOCAL_SHARED=$(LINK_SHARED)
LIBS=$(LOCAL_LIBS)

OBJS = \
../../../Common/MyWindows.o \
../../../Common/Alloc.o \
DllExports.o \
InBuffer.o \
OutBuffer.o \
StreamUtils.o \
crc.o  \
errhnd.o  \
getbits.o  \
rarvm.o  \
rdwrfn.o  \
resource.o  \
smallfn.o  \
system.o  \
unpack.o  \
Rar20Decoder.o  \
Rar20Multimedia.o  \
LZOutWindow.o  \
Rar29Decoder.o

include ../../../makefile.glb

