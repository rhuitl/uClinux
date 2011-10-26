#
# Makefile for mp3 player
#

# Define ColdFire to use ColdFire toolchain
ColdFire = 1

ifdef ColdFire
INCS	+= -I../mpegdec_lib 
CFLAGS	+= -DMPEGAUD_INT
LDLIBS   = ../mpegdec_lib/mpegdec.a $(LIBC) $(LIBM) $(LIBGCC)
FLTFLAGS += -s 8192
else
# x86 defines
LDLIBS	= ../mpegdec_lib/mpegdec-x86.a -lm -lc 
CFLAGS	+= -DMPEGAUD_INT -I../mpegdec_lib
INCS	= -I../mpegdec_lib
endif

ifdef ColdFire
EXEC	= mpegdec_demo
OBJS	= mpegdec_demo.o
else
EXEC	= mpegdec_demo
OBJS	= mpegdec_demo.o
endif

all: $(EXEC)

ifdef ColdFire
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
else
$(EXEC): $(OBJS)

$(EXEC)-x86: $(EXEC)
	cp $(EXEC) $(EXEC)-x86
endif

#test-x86: $(EXEC-x86) ref-drums.wav
#ifdef ColdFire
# swap byte order
#	sox -x -r 44100 -u -w -c 2 drums.raw drums.wav
#	sox -r 44100 -u -w -c 2 drums.raw drums.wav
#else
#	./$(EXEC) drums.mp3 drums.raw
#	sox -r 44100 -u -w -c 2 drums.raw drums.wav
#endif
#	play drums.wav

#
# Rules for making test files.
# raw - PCM samples from mpeg decoder.
# wav - wave file formatted of above.
# hex - hex dump of above. Suitable for use with diff.
#

.SUFFIXES: .hex .wav .raw 

.wav.hex:
	od -Ax -h --width=2 -v $< >$@

# Must swap ColdFire generated PCM data
.raw.wav:
ifdef ColdFire
	sox -r 44100 -s -w -c 2 -x $< $@
else
	sox -r 44100 -s -w -c 2 $< $@
endif


ref_drums.raw : drums.mp3 $(EXEC)-x86
	./$(EXEC)-x86 $< $@

ifndef ColdFire
drums.raw : drums.mp3 $(EXEC)-x86
	./$(EXEC)-x86 $< $@
else
drums.raw : drums.mp3 $(EXEC)
	echo "Please run $(EXEC) $< $@ on your ColdFire target"
endif

analyse: ref_drums.hex drums.hex
	diff --brief ref_drums.hex drums.hex

test: drums.wav ref_drums.wav
	play drums.wav
	play ref_drums.wav

clean:
	rm -f $(EXEC) $(OBJS) *.elf

realclean:
	rm -f $(EXEC) $(OBJS) *.wav *.raw *.hex *.*~
