# Generated automatically from Makefile.in by configure.
#***********************************************************************
#
# Makefile
#
# Makefile for Roaring Penguin's Linux PPPoE plugin.
#
# Copyright (C) 2001 Roaring Penguin Software Inc.
#
# This program may be distributed according to the terms of the GNU
# General Public License, version 2 or (at your option) any later version.
#
# $Id: Makefile.linux,v 1.7 2006/06/04 05:07:46 paulus Exp $
#***********************************************************************

DESTDIR = $(INSTROOT)@DESTDIR@
BINDIR = $(DESTDIR)/sbin
LIBDIR = $(DESTDIR)/lib/pppd/$(PPPDVERSION)

PPPDVERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../../patchlevel.h)

INSTALL	= install

# Version is set ONLY IN THE MAKEFILE!  Don't delete this!
VERSION=3.3

ifeq ($(CONFIG_USER_PPPD_WITH_DYNAMIC_PLUGINS),y)
CFLAGS += -fPIC
TARGET = pppoe.so pppoe-discovery
else
TARGET = libpppoe.o
endif
CFLAGS += -I../../../include/linux


all: $(TARGET)

pppoe-discovery: libplugin.a pppoe-discovery.o
	$(CC) -o pppoe-discovery pppoe-discovery.o libplugin.a

pppoe-discovery.o: pppoe-discovery.c
	$(CC) $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o pppoe-discovery.o pppoe-discovery.c

pppoe.so: libplugin.a plugin.o
	$(CC) -o pppoe.so -shared plugin.o libplugin.a

install: all
	$(INSTALL) -d -m 755 $(LIBDIR)
	$(INSTALL) -s -c -m 4550 pppoe.so $(LIBDIR)
	$(INSTALL) -d -m 755 $(BINDIR)
	$(INSTALL) -s -c -m 555 pppoe-discovery $(BINDIR)

clean:
	rm -f *.o *.so *.a

plugin.o: plugin.c
	$(CC) '-DRP_VERSION="$(VERSION)"' $(CFLAGS) -I../../..  -c -o plugin.o plugin.c

libplugin.a: discovery.o if.o common.o debug.o
	$(AR) -rc $@ $^

libpppoe.o: plugin.o discovery.o if.o common.o debug.o
	$(LD) -r -o $@ $^

discovery.o: discovery.c
	$(CC) $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o discovery.o discovery.c

if.o: if.c
	$(CC) $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o if.o if.c

debug.o: debug.c
	$(CC) $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o debug.o debug.c

common.o: common.c
	$(CC) $(CFLAGS) '-DVERSION="$(VERSION)"' -c -o common.o common.c

