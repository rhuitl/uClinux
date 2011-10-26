# FreeS/WAN library
# Copyright (C) 1998-2001  Henry Spencer.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.50 2002/03/27 23:08:24 mcr Exp $



include ../Makefile.inc
include ../Makefile.ver



MANDIR=$(MANTREE)/man3

SRCS=addrtoa.c addrtot.c addrtypeof.c anyaddr.c atoaddr.c \
	atoasr.c atosa.c atosubnet.c atoul.c copyright.c datatot.c \
	goodmask.c initaddr.c initsaid.c initsubnet.c keyblobtoid.c \
	optionsfrom.c pfkey_v2_build.c pfkey_v2_ext_bits.c pfkey_v2_parse.c \
	pfkey_v2_debug.c \
	portof.c prng.c rangetoa.c rangetosubnet.c sameaddr.c \
	satoa.c satot.c subnetof.c subnettoa.c subnettot.c \
	subnettypeof.c ttoaddr.c ttodata.c \
	ttosa.c ttosubnet.c ttoul.c ultoa.c ultot.c \
	ttoprotoport.c

OBJS=${SRCS:.c=.o} version.o

HDRS=freeswan.h internal.h
LIB=libfreeswan.a
# Original flags
CFLAGS=-I. $(USERCOMPILE)
CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wcast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast 

ARFLAGS=crvs
EXTHDRS=des.h
EXTLIBS=libdes.a
MANS=anyaddr.3 atoaddr.3 atoasr.3 atosa.3 atoul.3 goodmask.3 \
	initaddr.3 initsubnet.3 keyblobtoid.3 \
	optionsfrom.3 portof.3 prng.3 rangetosubnet.3 \
	sameaddr.3 subnetof.3 ttoaddr.3 ttodata.3 ttosa.3 ttoul.3 version.3
.PHONY:	all install clean l t lt tar check depend checkprograms



all:	$(EXTHDRS) $(LIB) $(EXTLIBS)
programs: all

install:
	mkdir -p $(MANDIR)
	for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $$f $(MANDIR)/ipsec_$$f || exit 1 ; \
		../utils/manlink $(MANDIR) ipsec_$$f ; \
	done

$(LIB):	$(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

$(OBJS):	$(HDRS)

# build version.c using version number from Makefile.ver
version.c:	version.in.c ../Makefile.ver
	sed '/"/s/xxx/$(IPSECVERSION)/' version.in.c >$@

des.h:
	ln -s ../libdes/des.h

libdes.a:	../libdes/libdes.a
	ln -f -s ../libdes/libdes.a

# yes, that's CFLAG=, not CFLAGS=
../libdes/libdes.a:
	cd ../libdes ; \
	if test " `arch | sed 's/^i[3456]/x/'`" = " x86" ; \
	then $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' TESTING='' x86-elf ; \
	else $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' libdes.a ; \
	fi

clean:
	rm -f $(LIB) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c
	cd ../libdes ; $(MAKE) clean



# developer-only stuff
l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	$(RANLIB) $(LIB)

t:	$(LIB)
	cp atosubnet.c try.c
	cc -DATOSUBNET_MAIN try.c $(LIB) -o try
	./try -r
	cp ttosubnet.c try1a.c
	cc -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	cp ttodata.c try2.c
	cc -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	cp atoasr.c try3.c
	cc -DATOASR_MAIN try3.c $(LIB) -o try3
	./try3 -r
	cp atosa.c try4.c
	cc -DATOSA_MAIN try4.c $(LIB) -o try4
	./try4 -r
	cp ttosa.c try4a.c
	cc -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	cp rangetosubnet.c try6.c
	cc -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r
	cp keyblobtoid.c try7.c
	cc -DKEYID_MAIN try7.c $(LIB) -o try7
	./try7
	cp prng.c try8.c
	cc -DPRNG_MAIN try8.c $(LIB) -o try8
	./try8 -r

lt:	$(LIB)
	$(MAKE) t
	cp optionsfrom.c try5.c
	cc -DTEST try5.c $(LIB) -o try5
	echo --foo --bar >try5in1
	echo --optionsfrom >>try5in1
	echo try5in2 >>try5in1
	echo --foo >try5in2
	./try5 --foo --bar --optionsfrom try5in1 --bar something

tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:
	echo no checks in lib right now.

depend:
	makedepend -Y -- $(CFLAGS) -- $(SRCS)

checkprograms:

# DO NOT DELETE

pfkey_v2_build.o:  freeswan.h ../pluto/constants.h
pfkey_v2_build.o: ../pluto/defs.h ../pluto/log.h ./pfkeyv2.h ./pfkey.h
pfkey_v2_ext_bits.o:  freeswan.h ./pfkeyv2.h ./pfkey.h
pfkey_v2_parse.o:  freeswan.h ../pluto/constants.h
pfkey_v2_parse.o: ../pluto/defs.h ../pluto/log.h ./pfkeyv2.h ./pfkey.h
pfkey_v2_debug.o:  freeswan.h ./pfkeyv2.h ./pfkey.h
