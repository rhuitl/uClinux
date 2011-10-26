#
# Makefile for mpegdec.lib
#

# Note: LITTLE_ENDIAN is defined in usr/include/sys/types.h
# Define MPEGAUD_INT for integer only decoder
MPEGAUD_INT = 1


ifdef CONFIG_COLDFIRE
# Define ASM_OPTIMIZE for 68k assmbly optimizations
68k_ASM = 1

# Define ColdFire to use ColdFire toolchain
ColdFire = 1

# Define ColdFireMAC to use the ColdFire multiply accumulate unit.
#ColdFireMAC = 1
endif

ifdef CONFIG_USER_SETKEY_SETKEY
CFLAGS += -DUSE_RC4 -I../rc4
endif

ifdef ColdFire
MYLIB= mpegdec.a
ifdef MPEGAUD_INT
CFLAGS	+= -DMPEGAUD_INT -DSPLIT_TABLE -DUSE_IMDCT_TABLE
endif
else
ifdef MPEGAUD_INT
CFLAGS	+= -DMPEGAUD_INT -DSPLIT_TABLE -DUSE_IMDCT_TABLE
endif
AR = ar 
# MYLIB= mpegdec-x86.a
MYLIB= mpegdec.a
endif

CFLAGS += -g -O1
ASFLAGS += -Wa,--register-prefix-optional

all: $(MYLIB)

OBJS= bitstr.o huff.o mpeg3dec.o mpegsub.o mpegtab.o mpegimdc.o

ifdef 68k_ASM
ifdef ColdFire
#CFLAGS += -DCOLDFIRE_ASM -DHACK
#OBJS += coldfire_mpegimda.o
CFLAGS += -DCOLDFIRE_ASM_2
OBJS += coldfire_mpegsubb.o
ifdef ColdFireMAC
CFLAGS += -DCOLDFIRE_MAC
endif
else
OBJS += mpegimda.o  mpegsubb.o
CFLAGS += -DASM_OPTIMIZE -DHACK
endif
endif

ifdef ALL_FORMATS
OBJS += mpeg1dec.o mpeg2dec.o mpegdec.o 
else
OBJS += mp3onlydec.o 
endif


bitstr.o: bitstr.c bitstr.h

huff.o: huff.c defs.h mpegaud.h mpegtab.h bitstr.h huff.h

mpeg1dec.o: mpeg1dec.c defs.h bitstr.h mpegaud.h mpegtab.h mpegsub.h \
            mpeg1dec.h bitstr.h huff.h mpegimda.h

mpeg2dec.o: mpeg2dec.c defs.h bitstr.h mpegaud.h mpegtab.h mpegsub.h \
            mpeg2dec.h bitstr.h huff.h mpegimda.h

mpeg3dec.o: mpeg3dec.c defs.h bitstr.h mpegaud.h mpegtab.h mpegsub.h \
            mpegsubb.h mpeg3dec.h bitstr.h huff.h mpegimda.h

mpegdec.o: mpegdec.c defs.h mpegaud.h mpeg1dec.h mpeg2dec.h mpeg3dec.h \
           mpegdec.h mpegtab.h bitstr.h huff.h

mpegsub.o: mpegsub.c defs.h mpegaud.h mpegsub.h mpegtab.h mpegsubb.h \
           mpegimda.h bitstr.h huff.h mpegimda.h

mpegtab.o: mpegtab.c defs.h mpegaud.h mpegtab.h bitstr.h huff.h

ifdef 68K_ASM
mpegimda.o: mpegimda.a

mpegsubb.o: mpegsubb.a
endif

mpegimdc.o: mpegimdc.c mpegimdc.h defs.h mpegaud.h

$(MYLIB): $(OBJS)
	$(AR) -crusv $(MYLIB) $(OBJS)

clean:
	rm -f $(OBJS) $(MYLIB)

.S.o:
	$(CC) $(CFLAGS) $(ASFLAGS) -c $<
