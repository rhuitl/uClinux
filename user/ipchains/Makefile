.EXPORT_ALL_VARIABLES:
#
#	Makefile for the ipchain package: ripped straight from ipfwadm.
#	(C) Paul Russell 1998 All rights reserved.
#       EMail complaints to ipchains@wantree.com.au.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#


# CC	= gcc
# COPTS   = -g -O
# CFLAGS	= -Wall -Wunused $(COPTS)
EXEC = ipchains
OBJS = ipchains.o
SBIN	= /sbin
MANDIR	= /usr/man
INSTALL = install
TEX	= latex

all:		ipchains ipfw.4 ipchains.8

ipchains:	$(OBJS) libipfwc/libipfwc.a libipfwc/libipfwc.h libipfwc/ipfwc_kernel_headers.h
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) libipfwc/libipfwc.a

romfs:
	$(ROMFSINST) /bin/$(EXEC)

install:	ipchains ipfw.4 ipchains.8
	@-mv $(SBIN)/ipchains $(SBIN)/ipchains.old
	$(INSTALL) -m 0755 -o root -g root ipchains $(SBIN)/
	$(INSTALL) -m 0644 -o root -g root ipfw.4 $(MANDIR)/man4/
	$(INSTALL) -m 0644 -o root -g root ipchains.8 $(MANDIR)/man8/

uninstall:
	-rm -f $(SBIN)/ipchains $(MANDIR)/man4/ipfw.4 $(MANDIR)/man8/ipchains.8
	@-mv $(SBIN)/ipchains.old $(SBIN)/ipchains && echo Restored old ipchains from $(SBIN)/ipchains.old...

libipfwc/libipfwc.a:
	cd libipfwc/ && $(MAKE) libipfwc.a

distclean: clean
	rm -f HOWTO.txt

subclean:
	cd libipfwc/ && $(MAKE) clean

clean: subclean
	rm -f $(EXEC) *.o core $(EXEC).elf $(EXEC).gdb
