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


CFLAGS += -DHAVE_CONFIG_H -I. -I.. 

SHELL = /bin/sh

OBJECTS =  long-options.o xstrtol.o xstrtoul.o error.o

all: libzmodem.a

libzmodem.a: $(OBJECTS) 
	-rm -f libzmodem.a
	$(AR) cru libzmodem.a $(OBJECTS) 
	$(RANLIB) libzmodem.a

error.o: error.c ../config.h
long-options.o: long-options.c ../config.h getopt.h long-options.h
xstrtol.o: xstrtol.c ../config.h xstrtol.h
xstrtoul.o: xstrtoul.c xstrtol.c ../config.h xstrtol.h

clean:
	-rm -f *.o libzmodem.a

