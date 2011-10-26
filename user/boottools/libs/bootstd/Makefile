##
#* Makefile - uCbootloader system call library makefile
#*
#* Copyright (c) 2006  Arcturus Networks Inc.
#*	by Oleksandr G Zhadan <www.ArcturusNetworks.com>
#*
#* All rights reserved.
#*
#* This material is proprietary to Arcturus Networks Inc. and, in
#* addition to the above mentioned Copyright, may be subject to
#* protection under other intellectual property regimes, including
#* patents, trade secrets, designs and/or trademarks.
#*
#* Any use of this material for any purpose, except with an express
#* license from Arcturus Networks Inc. is strictly prohibited.
#* 
#*/

CFLAGS += -funsigned-char -Wall -Iinclude
CFLAGS += -I$(KERNELDIR)/include

BSCSRC = bsc_reset.c bsc_gethwaddr.c bsc_getserialnum.c bsc_eraseall.c \
	bsc_setenv.c bsc_getenv.c bsc_readenv.c bsc_setpmask.c bsc_version.c \
	bsc_free.c bsc_eraseenv.c bsc_printenv.c bsc_semaphore.c

BSCOBJS = bsc_reset.o bsc_gethwaddr.o bsc_getserialnum.o bsc_eraseall.o \
	bsc_setenv.o bsc_getenv.o bsc_readenv.o bsc_setpmask.o bsc_version.o \
	bsc_free.o bsc_eraseenv.o bsc_printenv.o bsc_semaphore.o

BSCLIB = lib/libbsc.a

all: ${BSCLIB}

${BSCLIB}:
	[ -d lib ] || mkdir lib  
	${CC} -c ${CFLAGS} $(BSCSRC) && ${AR} -rc ${BSCLIB} $(BSCOBJS) && ${RANLIB} ${BSCLIB}

.PHONY: ${BSCLIB}

btest: ${BSCLIB}
	make -C test

clean:
	make -C test clean 
	rm -f ${BSCLIB} *.elf *.gdb *.o *.bak core
