# FreeS/WAN subdir makefile
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
# RCSID $Id: Makefile,v 1.8 2002/04/02 04:08:22 mcr Exp $

TOPDIR=../../..
OBJS = uml_netjig.o
OPTIONS=-DARP_PROCESS

# To use the netdissect option, you have to have a very recent (pre-alpha) copy
# of tcpdump source code from www.tcpdump.org. For now, leave it unset.
#NETDISSECTH=-DNETDISSECT -I/home/mcr/src/tcpdump
#NETDISSECTLIB=-L/home/mcr/src/linux/i386/tcpdump -lnetdissect

# To read/write files, you need to have libpcap (-devel if on RH) installed.
PCAPH=-I/usr/include/pcap
PCAPLIB=-lpcap
#PCAPH=-I/home/mcr/src/libpcap
#PCAPLIB=-L/home/mcr/src/linux/i386/libpcap -lpcap

# to decode ESP packets, you need crypto, which you can get from ssl.
OPENSSL=-L/usr/local/ssl/lib -lcrypto

CFLAGS = -g -Wall ${PCAPH} ${NETDISSECTH} ${OPTIONS}
LIBS = ${NETDISSECTLIB} ${PCAPLIB} 


include $(TOPDIR)/Makefile.inc

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

programs: uml_netjig

checkprograms: uml_netjig

uml_netjig : $(OBJS)
	$(CC) $(CFLAGS) -o uml_netjig $(OBJS) $(LIBS)

clean : 
	rm -f uml_netjig $(OBJS) *~

install :
	install -d $(BINDIR)
	install -s uml_netjig $(BINDIR)

check: 
