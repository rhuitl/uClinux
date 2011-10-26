# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
# RCSID $Id: Makefile,v 1.28 2002/01/30 00:17:05 mcr Exp $


include ../../Makefile.inc



CC=gcc
CFLAGS=$(USERCOMPILE) -I../net/ipsec -I../../lib

CFLAGS+= $(USERCOMPILE)
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

ALL=spi eroute spigrp tncfg klipsdebug pf_key
MANDIR8=$(MANTREE)/man8
MANDIR5=$(MANTREE)/man5
FREESWANLIB=../../lib/libfreeswan.a

all: $(ALL)

programs: all

check: $(ALL)

install: $(ALL)
	mkdir -p $(BINDIR) $(MANDIR8) $(MANDIR5)
	$(INSTALL) $(ALL) $(BINDIR)
	for f in $(addsuffix .8, $(ALL)) ; do \
		$(INSTALL) $$f $(MANDIR8)/ipsec_$$f || exit 1 ; done
	for f in $(addsuffix .5, $(ALL) version pf_key) ; do \
		$(INSTALL) $$f $(MANDIR5)/ipsec_$$f || exit 1 ; done

constants.o : ../../pluto/constants.c ../../pluto/constants.h
	$(CC) $(CFLAGS) -c -o $@ $<

alg_info.o : ../../pluto/alg_info.c ../../pluto/alg_info.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $<

kernel_alg.o : ../../pluto/kernel_alg.c ../../pluto/kernel_alg.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $<

spi: spi.o constants.o alg_info.o kernel_alg.o
	$(CC) $(DFLAGS) -o $@ $^ $(FREESWANLIB)

eroute: eroute.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

spigrp: spigrp.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

tncfg: tncfg.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

pf_key: pf_key.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

klipsdebug: klipsdebug.o
	$(CC) $(DFLAGS) -o $@ $? $(FREESWANLIB)

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

clean:
	rm -f *.o $(ALL)

checkprograms:

#
# $Log: Makefile,v $
# Revision 1.28  2002/01/30 00:17:05  mcr
# 	replace -O2 with $(USERCOMPILE) in CFLAGS to match other Makefiles.
#
# Revision 1.27  2002/01/17 04:38:45  rgb
# Take compile options from top level Makefile.inc
# Change the "programs" target to depend on the "all" target.
#
# Revision 1.26  2001/12/05 07:21:19  rgb
# Make sure KLIPS utils get compiled first time through.
#
# Revision 1.25  2001/11/27 16:27:07  mcr
# 	added new "checkprograms" target to deal with programs that
# 	are required for "make check", but that may not be ready to
# 	build for every user due to external dependancies.
#
# Revision 1.24  2001/11/27 05:08:17  rgb
# Remove temporary version.o dependancy.
#
# Revision 1.23  2001/11/26 09:24:28  rgb
# Added version.o to klipsdebug.
#
# Revision 1.22  2001/11/23 07:23:14  mcr
# 	pulled up klips2 Makefile and pf_key code.
#
# Revision 1.21  2001/10/30 17:42:01  mcr
# 	make all destination dirs used for installation.
#
# Revision 1.20  2001/10/24 14:41:42  henry
# Makefile.inc
#
# Revision 1.17.4.3  2001/10/18 00:13:30  mcr
# 	fix Makefile to reflect name of program is "pf_key" not "pfkey"
#
# Revision 1.17.4.2  2001/10/17 23:25:37  mcr
# 	added "pk_key" program to dump raw kernel pf messages.
# 	(program is still skeletal)
#
# Revision 1.17.4.1  2001/10/01 03:53:08  mcr
# 	changes for UML build (main branch)
#
# Revision 1.17.2.1  2001/09/25 01:31:55  mcr
# 	added usage of $(DESTDIR)
# 	added setting of FREESWANLIB.
#
# Revision 1.17  2001/06/14 19:35:13  rgb
# Update copyright date.
#
# Revision 1.16  2000/06/30 06:20:25  rgb
# Add version.5 and pf_key.5 to the list of manpages to be installed.
#
# Revision 1.15  2000/06/28 05:51:23  rgb
# Install section 5 manpages.
#
# Revision 1.14  2000/01/21 09:44:29  rgb
# Added compiler switches to be a lot more fussy.
#
# Revision 1.13  1999/04/11 00:12:07  henry
# GPL boilerplate
#
# Revision 1.12  1999/04/06 04:54:37  rgb
# Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
# patch shell fixes.
#
# Revision 1.11  1999/04/03 05:39:06  henry
# install -d doesn't do what I thought
#
# Revision 1.10  1999/04/03 05:23:23  henry
# use INSTALL
#
# Revision 1.9  1998/11/12 21:11:21  rgb
# Change default binary install directory from /usr/local/sbin to
# /usr/local/lib/ipsec.
#
# Revision 1.8  1998/11/07 05:38:54  henry
# changes for manpage ipsec_ prefix
#
# Revision 1.7  1998/07/28 00:08:07  rgb
# Add freeswan lib.
#
# Revision 1.6  1998/06/11 05:40:52  rgb
# Install manpages when binaries are installed.
#
# Revision 1.5  1998/05/12 02:28:07  rgb
# Utils can now be compiled before kernel install/config.
#
# Revision 1.4  1998/05/06 03:35:40  rgb
# Changed make install from an 'mv' to a 'cp'.
#
# Revision 1.3  1998/04/23 21:09:16  rgb
# Added a userspace util to change kernelspace debug switches.
#
# Revision 1.2  1998/04/14 14:07:01  rgb
# Permanently remove setsa.c and addrt.c from the distribution and fix the
# Makefile.
#
# Revision 1.1.1.1  1998/04/08 05:35:09  henry
# RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
#
# Revision 0.5  1997/06/03 04:31:55  ji
# Added esp 3des-md5-96.
# Added transport mode configuration utility.
#
# Revision 0.4  1997/01/15 01:38:21  ji
# Changed to include setsa.c
#
# Revision 0.3  1996/11/20 14:51:32  ji
# Fixed problems with #include paths.
# Changed (incorrect) references to ipsp into ipsec.
#
#
