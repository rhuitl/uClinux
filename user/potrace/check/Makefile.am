## Copyright (C) 2001-2007 Peter Selinger.
## This file is part of Potrace. It is free software and it is covered
## by the GNU General Public License. See the file COPYING for details.

## Process this file with automake to produce Makefile.in

check_PROGRAMS = pgmdiff
check_SCRIPTS = input-check.sh backend-check.sh potrace-check.sh postscript-check.sh pdf-check.sh mkbitmap-check.sh

TESTS = $(check_SCRIPTS)

EXTRA_DIST = $(TESTS) missing.sh data1.pbm data1.pgm data1.ppm data1.bmp1 data1.bmp4 data1.bmp8 data1.bmp24 data1.bmp4r data1.bmp8r data1.pgm.out data1.pbm.gs data1.pbm.rot data1.pgm.rot data2.ppm data2.pbm.out1 data2.pbm.out2 data3.pgm


pgmdiff_SOURCES = pgmdiff.c
pgmdiff_LDADD = ../src/greymap.o -lm
pgmdiff_DEPENDENCIES = ../src/greymap.o

../src/greymap.o:
	(cd ../src && $(MAKE) $(AM_MAKEFLAGS) greymap.o)
