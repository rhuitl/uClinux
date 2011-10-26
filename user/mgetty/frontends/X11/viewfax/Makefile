# Makefile for viewfax
# Copyright (C) 1990, 1995, 2004  Frank D. Cringle.

# This file is part of viewfax - g3/g4 fax processing software.
#      
# viewfax is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#      
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#      
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

VERS = 2.6

####### Site-specific definitions #######
# Destination directories and installation program for make install
BINDIR = /usr/local/bin
LIBDIR = /usr/local/lib
MANDIR	= /usr/local/man/man1
INSTALL = /usr/bin/install
RM = rm -f
# Location of help file
HELP = \"$(LIBDIR)/viewfax.tif\"
# optimisation level, debug etc
OPT = -g -O2 -Wno-uninitialized -ansi -pedantic
# C compiler and libraries
# vanilla sysv
#CC = cc
#CFLAGS = $(OPT) -DHELPFILE=$(HELP)
#LDFLAGS = $(OPT)
#LIBS = -lsocket
# vanilla BSD
#CC = cc
#CFLAGS = -DBSD $(OPT) -DHELPFILE=$(HELP)
#LDFLAGS = $(OPT)
#LIBS =
# sun solaris2 with gcc on supersparc:
#CC = gcc
#CFLAGS = -Wall $(OPT) -DHELPFILE=$(HELP) -msupersparc -I/usr/openwin/include
#LDFLAGS = $(OPT) -L/usr/openwin/lib -R/usr/openwin/lib
#LIBS =
# linux
CC = gcc
CFLAGS = $(OPT) -DHELPFILE=$(HELP)
LDFLAGS = $(OPT) -L/usr/X11R6/lib
LIBS =

####### End of configurable definitions #######
OBJS = viewfax.o faxinput.o faxinit.o faxexpand.o

viewfax:	$(OBJS)
	$(CC) $(LDFLAGS) -o viewfax $(OBJS) -lX11 $(LIBS)

g3hack:		g3hack.c

install: viewfax
	$(INSTALL) -s -m 755 viewfax $(BINDIR)
	$(INSTALL) -m 644 viewfax.man $(MANDIR)/viewfax.1
	$(INSTALL) -m 644 viewfax.tif $(LIBDIR)

D = viewfax-$(VERS)
FILES = $D/README $D/COPYING $D/ChangeLog $D/Imakefile $D/Makefile \
	$D/faxexpand.c $D/faxexpand.h $D/faxinput.c $D/faxinit.c \
	$D/viewfax.c $D/viewfax.man $D/viewfax.tif $D/viewfax.help \
	$D/g3hack.c $D/README.kde

viewfax.tif:	viewfax.help
	enscript -B -e^ -T 16 -X ps -o viewfax.ps viewfax.help
	gs -sDEVICE=faxg3 -sOutputFile=viewfax.g3 -dNOPAUSE \
		-q -dSAFER viewfax.ps -c quit
	fax2tiff -M -8 -o viewfax.tif viewfax.g3
	$(RM) viewfax.ps viewfax.g3

tar:;	(cd ..; tar cf - $(FILES) | gzip -9 >$D/$D.tar.gz)

shar:;	(cd ..; shar -a -n$D -M -sfdc@cliwe.ping.de -c -o $D/part -l64 $(FILES))

clean:;	$(RM) *.o *~ core

viewfax.o:	faxexpand.h
faxinput.o:	faxexpand.h
faxinit.o:	faxexpand.h
faxexpand.o:	faxexpand.h
faxcompress.o:	faxexpand.h
