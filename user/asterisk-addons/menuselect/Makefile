#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for Menuselect
#
# Copyright (C) 2005-2006, Digium, Inc.
#
# Russell Bryant <russell@digium.com>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

.PHONY: clean dist-clean distclean

MENUSELECT_OBJS:=menuselect.o menuselect_curses.o strcompat.o
MENUSELECT_CFLAGS:=-g -c -D_GNU_SOURCE
MENUSELECT_LIBS:=mxml/libmxml.a

GMENUSELECT_OBJS:=menuselect.o menuselect_gtk.o strcompat.o
ifeq ($(GTK2_LIB),)
  GMENUSELECT_OBJS:=$(filter-out menuselect_gtk.o,$(GMENUSELECT_OBJS)) menuselect_stub.o
endif
GMENUSELECT_CFLAGS:=$(GTK2_INCLUDE)
GMENUSELECT_LIBS:=mxml/libmxml.a $(GTK2_LIB)

-include makeopts

ifneq ($(NCURSES_LIB),)
  MENUSELECT_LIBS+=$(NCURSES_LIB)
  MENUSELECT_INCLUDE:=$(NCURSES_INCLUDE)
else
 ifneq ($(CURSES_LIB),)
  MENUSELECT_LIBS+=$(CURSES_LIB)
  MENUSELECT_INCLUDE:=$(CURSES_INCLUDE)
 else
  MENUSELECT_OBJS:=$(filter-out menuselect_curses.o,$(MENUSELECT_OBJS)) menuselect_stub.o
 endif
endif

all: autoconfig.h
	@$(MAKE) menuselect

autoconfig.h:
	@./configure $(CONFIGURE_SILENT) CC= LD= AR=

_gmenuselect: autoconfig.h 
	@$(MAKE) gmenuselect

gmenuselect: mxml/libmxml.a $(GMENUSELECT_OBJS)
	$(CC) -g -Wall -o $@ $(GMENUSELECT_OBJS) $(GMENUSELECT_LIBS)

menuselect: mxml/libmxml.a $(MENUSELECT_OBJS)
	$(CC) -g -Wall -o $@ $(MENUSELECT_OBJS) $(MENUSELECT_LIBS)

menuselect.o: menuselect.c menuselect.h
	$(CC) -Wall $(CFLAGS) -o $@ $(MENUSELECT_CFLAGS) $<

menuselect_curses.o: menuselect_curses.c menuselect.h
	$(CC) -Wall $(CFLAGS) -o $@ $(MENUSELECT_CFLAGS) $(MENUSELECT_INCLUDE) $<

menuselect_stub.o: menuselect_stub.c menuselect.h
	$(CC) -Wall $(CFLAGS) -o $@ $(MENUSELECT_CFLAGS) $(MENUSELECT_INCLUDE) $<

menuselect_gtk.o: menuselect_gtk.c menuselect.h
	gcc -Wall $(CFLAGS) -o $@ $(MENUSELECT_CFLAGS) $(GMENUSELECT_CFLAGS) $<

strcompat.o: strcompat.c
	$(CC) -Wall $(CFLAGS) -o $@ $(MENUSELECT_CFLAGS) $<

mxml/libmxml.a:
	@if test ! -f mxml/Makefile ; then cd mxml && ./configure && cd .. ; fi
	@$(MAKE) -C mxml libmxml.a

clean:
	rm -f menuselect gmenuselect *.o
	@if test -f mxml/Makefile ; then $(MAKE) -C mxml clean ; fi

dist-clean: distclean

distclean: clean
	@if test -f mxml/Makefile ; then $(MAKE) -C mxml distclean ; fi
	rm -f autoconfig.h config.status config.log makeopts
	rm -rf autom4te.cache
