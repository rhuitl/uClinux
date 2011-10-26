# ###############################################################
#
# Makefile for the GPL speedtouch USB driver 
#
# Written by Francois Rogler <francois@rogler.org>
#
# $Id: Makefile,v 1.2 2005-01-20 05:24:01 damion Exp $
#
# ###############################################################

# ###############################################################
# Makefile variables
# ###############################################################

# Warning levels
CWARN0 = -Wall
CWARN1 = $(CWARN0) -Wwrite-strings -Wshadow
CWARN2 = $(CWARN1) -Wcast-align -Wcast-qual -Waggregate-return
CWARN3 = $(CWARN2) -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CWARN4 = $(CWARN3) -Wconversion -Winline -Wtraditional
CWARN  = $(CWARN0)


# Vrac
SHELL = /bin/sh
CONFIGURE_ARGS = 


rootdir=$(ROOTDIR)/user/speedtouch

# Driver version
VERSION=1.3

# Installation directories
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libexecdir=${exec_prefix}/libexec
datadir=${prefix}/share
sysconfdir=/etc
libdir=${exec_prefix}/lib
includedir=${prefix}/include
oldincludedir=/usr/include
infodir=${prefix}/info
mandir=${prefix}/man
doc=${rootdir}/doc-linux

srcdir=${rootdir}/src
make_bindir=${rootdir}/bin
include= -I.
INSTALL=/usr/bin/install -c
installuser=root

# C compiler
#CC=gcc

# C compiler options
THREAD_LIBS=-pthread
USE_SYSLOG=-DUSE_SYSLOG
PUSB_SOURCE=pusb-linux.c

#CFLAGS= -O2
ST_CFLAGS=$(CWARN) $(include) $(CFLAGS)
ST_COMPILE=modem_run

# Linker options
LINK_OPTS=$(LDFLAGS)

LIBS=$(LDLIBS)

DEFS=$(CFLAGS)

#RPM Variables
RPM_ROOT=/usr/src/redhat

# ###############################################################
# Makefile Rules
# ###############################################################

DIST_FILES = atm.c         Makefile.in  pppoa2.c   pusb.h \
             atm.h         firmware.c   modem.h    pppoa3.c \
             pusb-linux.c  crc.c        firmware.h modem_run.c \
             pppoa3.h      smallsem.c   crc.h      n_hdlc.c.diff \
             pusb-bsd.c    smallsem.h   pusb-linux.h boot.v123.S \
             boot.v123.bin speedtouch-setup.in speedtouch-start.in \
			 speedtouch-stop.in mutex.h mutex.c

OBJS_M   = firmware.o \
           pusb.o \
           modem_run.o \
           crc.o \
           smallsem.o \
		   mutex.o

OBJS_P2 =  pusb.o \
           pppoa2.o \
           crc.o \
           atm.o \
           smallsem.o

OBJS_P3 =  pusb.o \
           pppoa3.o \
           crc.o \
           atm.o

all : $(ST_COMPILE)

${make_bindir} : $(ST_COMPILE)
	@test -d "${make_bindir}" || mkdir "${make_bindir}"
	cp $(ST_COMPILE) "${make_bindir}"

modem_run : $(OBJS_M)
	$(CC) $(ST_CFLAGS) $(OBJS_M) $(LINK_OPTS) -o modem_run $(LIBS)

pppoa2 : $(OBJS_P2)
	$(CC) $(ST_CFLAGS) $(OBJS_P2) $(LINK_OPTS) -o pppoa2 $(LIBS)

pppoa3 : $(OBJS_P3)
	$(CC) $(ST_CFLAGS) $(OBJS_P3) $(THREAD_LIBS) $(LINK_OPTS) -o pppoa3 $(LIBS)

firmware_extract : firmware_main.o
	$(CC) $(ST_CFLAGS) $(LINK_OPTS) firmware_main.o -o firmware_extract

modem_run.o : modem_run.c modem.h
	$(CC) $(ST_CFLAGS) $(USE_SYSLOG) -DVERSION=\"$(VERSION)\" -c modem_run.c

pppoa2.o : pppoa2.c pppoa3.h
	$(CC) $(ST_CFLAGS) $(USE_SYSLOG) -DVERSION=\"$(VERSION)\" -c pppoa2.c

pppoa3.o : pppoa3.c pppoa3.h
	$(CC) $(ST_CFLAGS) $(USE_SYSLOG) -D_REENTRANT -D_THREAD_SAFE -DVERSION=\"$(VERSION)\" -c pppoa3.c

pusb.o : pusb.h $(PUSB_SOURCE)
	$(CC) $(ST_CFLAGS) -DVERSION=\"$(VERSION)\" -D_REENTRANT -D_THREAD_SAFE -o pusb.o -c $(PUSB_SOURCE)

smallsem.o : smallsem.c smallsem.h
	$(CC) $(ST_CFLAGS) -DVERSION=\"$(VERSION)\" -c smallsem.c

crc.o: crc.c crc.h
	$(CC) $(ST_CFLAGS) -D_REENTRANT -D_THREAD_SAFE -DVERSION=\"$(VERSION)\" -c crc.c

atm.o: atm.c atm.h
	$(CC) $(ST_CFLAGS) -D_REENTRANT -D_THREAD_SAFE -DVERSION=\"$(VERSION)\" -c atm.c

firmware.o : firmware.c firmware.h
	$(CC) $(ST_CFLAGS) -DVERSION=\"$(VERSION)\" -c firmware.c

firmware_main.o : firmware.c crc.c firmware.h
	$(CC) $(ST_CFLAGS) -DSTANDALONE_EXTRACTER -DVERSION=\"$(VERSION)\" -o firmware_main.o -c firmware.c

dist:
	mkdir "$(rootdir)/speedtouch-$(VERSION)/src"
	cp -f $(DIST_FILES) "$(rootdir)/speedtouch-$(VERSION)/src"

clean :
	rm -f *.o $(ST_COMPILE) firmware_extract firmware_main.o

distclean : clean
	rm -f Makefile

install:
	$(INSTALL) -d "$(bindir)"
	$(INSTALL) -m 0755 speedtouch-setup "$(bindir)"
	$(INSTALL) -m 0755 speedtouch-start "$(bindir)"
	$(INSTALL) -m 0755 speedtouch-stop  "$(bindir)"
	$(INSTALL) -d "$(sysconfdir)/speedtouch"

uninstall:
	$(RM) "$(bindir)/speedtouch-setup"
	$(RM) "$(bindir)/speedtouch-start"
	$(RM) "$(bindir)/speedtouch-stop"

romfs:
	$(ROMFSINST) /bin/modem_run
	if test ! -d $(ROMFSDIR)/etc/speedtouch; then \
	mkdir $(ROMFSDIR)/etc/speedtouch; fi
	$(ROMFSINST) /etc/speedtouch/KQD6_3.012
	$(ROMFSINST) /etc/speedtouch/ZZZL_3.012
