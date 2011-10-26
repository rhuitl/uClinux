#
# Makefile for mp3 player and library.
#

EXEC	= mp3play
OBJS	= mp3play.o http.o

CFLAGS	 += -Impegdec_lib -DMPEGAUD_INT -Irc4
MP3LIB   = mpegdec_lib/mpegdec.a
RC4LIB   = rc4/librc4.a
FLTFLAGS += -s 8192

ifdef CONFIG_USER_MP3PLAY_SWAP_WD
CFLAGS += -DSWAP_WD
endif

all: $(EXEC)

$(EXEC): mp3lib rc4lib $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(MP3LIB) $(RC4LIB) $(LDLIBS)

mp3lib:
	$(MAKE) -C mpegdec_lib

rc4lib:
	$(MAKE) -C rc4

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	$(MAKE) -C mpegdec_lib clean
	$(MAKE) -C rc4 clean
	rm -f $(EXEC) $(OBJS) *.elf *.gdb

