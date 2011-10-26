# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.3 from Makefile.am

# Copyright (C) 1994, 1995, 1996, 1997, 1998 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.


CFLAGS += -DHAVE_CONFIG_H -I. -I.. -I../lib -DNFGVMIN

SHELL = /bin/sh

bin_PROGRAMS=lrz lsz
lrz_SOURCES=lrz.c timing.c zperr.c zreadline.c crctab.c rbsb.c zm.c protname.c tcp.c lsyslog.c canit.c
lsz_SOURCES=lsz.c timing.c zperr.c zreadline.c crctab.c rbsb.c zm.c protname.c tcp.c lsyslog.c canit.c

LDADD = ../lib/libzmodem.a 

INCLUDES = -I.. -I$(srcdir) -I$(top_srcdir)/src -I../intl -I$(top_srcdir)/lib

DEFS = -DNFGVMIN -DHAVE_CONFIG_H -DLOCALEDIR=\"$(localedir)\"

PROGRAMS =  $(bin_PROGRAMS)

lrz_OBJECTS =  lrz.o timing.o zperr.o zreadline.o crctab.o \
rbsb.o zm.o protname.o tcp.o lsyslog.o canit.o
lrz_LDADD = $(LDADD)
lrz_DEPENDENCIES =  ../lib/libzmodem.a
lrz_LDFLAGS = 

lsz_OBJECTS =  lsz.o timing.o zperr.o zreadline.o crctab.o \
rbsb.o zm.o protname.o tcp.o lsyslog.o canit.o
lsz_LDADD = $(LDADD)
lsz_DEPENDENCIES =  ../lib/libzmodem.a
lsz_LDFLAGS = 

SOURCES = $(lrz_SOURCES) $(lsz_SOURCES)
OBJECTS = $(lrz_OBJECTS) $(lsz_OBJECTS)

all: Makefile $(ANSI2KNR) $(PROGRAMS) $(HEADERS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_LRZSZ_LRZ /bin/lrz
	$(ROMFSINST) -e CONFIG_USER_LRZSZ_LSZ /bin/lsz

lrz: $(lrz_OBJECTS) $(lrz_DEPENDENCIES)
	@rm -f lrz
	$(CC) $(LDFLAGS) -o $@ $(lrz_OBJECTS) $(lrz_LDADD) $(LIBS) $(LDLIBS)

lsz: $(lsz_OBJECTS) $(lsz_DEPENDENCIES)
	@rm -f lsz
	$(CC) $(LDFLAGS) -o $@ $(lsz_OBJECTS) $(lsz_LDADD) $(LIBS) $(LDLIBS)

canit.o: canit.c zglobal.h ../config.h zmodem.h ../lib/getopt.h

crctab.o: crctab.c

lrz.o: lrz.c zglobal.h ../config.h zmodem.h ../lib/getopt.h timing.h \
	../lib/long-options.h ../lib/xstrtoul.h ../lib/xstrtol.h \
	../lib/error.h

lsyslog.o: lsyslog.c ../config.h zglobal.h zmodem.h

lsz.o: lsz.c zglobal.h ../config.h zmodem.h ../lib/getopt.h timing.h \
	../lib/long-options.h ../lib/xstrtoul.h ../lib/xstrtol.h \
	../lib/error.h

protname.o: protname.c zglobal.h ../config.h zmodem.h

rbsb.o: rbsb.c zglobal.h ../config.h zmodem.h

tcp.o: tcp.c ../config.h zglobal.h zmodem.h ../lib/error.h

timing.o: timing.c zglobal.h ../config.h zmodem.h timing.h

zm.o: zm.c zglobal.h ../config.h zmodem.h

zperr.o: zperr.c zglobal.h ../config.h zmodem.h

zreadline.o: zreadline.c zglobal.h ../config.h zmodem.h ../lib/error.h

clean:
	-rm -f *.o lrz lsz *.gdb *.elf

