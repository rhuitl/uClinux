#
# Makefile
#
# This is the Makefile for libpvf.
#
# $Id: Makefile,v 1.4 1998/09/09 21:06:41 gert Exp $
#

GSMOBJS=code.o decode.o gsm_create.o gsm_decode.o gsm_destroy.o gsm_encode.o \
	gsm_option.o code.o decode.o long_term.o lpc.o preprocess.o rpe.o \
	short_term.o add.o table.o

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: libmgsm.a

libmgsm.a: $(GSMOBJS)
	$(RM) -f libmgsm.a
	$(AR) $(ARFLAGS) libmgsm.a $(GSMOBJS)
	-$(RANLIB) libmgsm.a

install:

clean:
	@$(RM) -f libmgsm.a $(GSMOBJS)

fullclean: clean

include depend
