## Copyright (C) 2001-2007 Peter Selinger.
## This file is part of Potrace. It is free software and it is covered
## by the GNU General Public License. See the file COPYING for details.

## Process this file with automake to produce Makefile.in

#----------------------------------------------------------------------
# programs:

bin_PROGRAMS = potrace mkbitmap
noinst_PROGRAMS = potracelib_demo

potrace_SOURCES = main.c main.h bitmap_io.c bitmap_io.h backend_eps.c	   \
 backend_eps.h flate.c flate.h lists.h greymap.c greymap.h render.c	   \
 render.h backend_pgm.c backend_pgm.h backend_svg.c backend_svg.h	   \
 backend_gimp.c backend_gimp.h backend_xfig.c backend_xfig.h		   \
 backend_pdf.c backend_pdf.h lzw.c lzw.h bitops.h auxiliary.h potracelib.h \
 bitmap.h curve.h platform.h progress.h
potrace_LDADD = libpotrace.a @EXTRA_OBJS@ -lm @EXTRA_LIBS@
potrace_DEPENDENCIES = libpotrace.a @EXTRA_OBJS@

mkbitmap_SOURCES = mkbitmap.c bitmap_io.c bitmap_io.h greymap.c	\
 greymap.h platform.h
mkbitmap_LDADD = @EXTRA_OBJS@ -lm
mkbitmap_DEPENDENCIES = @EXTRA_OBJS@

potracelib_demo_SOURCES = potracelib_demo.c
potracelib_demo_LDADD = libpotrace.a -lm
potracelib_demo_DEPENDENCIES = libpotrace.a

#----------------------------------------------------------------------
# static libraries:

noinst_LIBRARIES = libpotrace.a
libpotrace_a_SOURCES = curve.c curve.h trace.c trace.h decompose.c	\
 decompose.h potracelib.c potracelib.h lists.h auxiliary.h bitmap.h	\
 progress.h

#----------------------------------------------------------------------
# dynamic libraries:

#lib_LTLIBRARIES = libpotrace.la
#libpotrace_la_SOURCES = curve.c curve.h trace.c trace.h decompose.c	\
# decompose.h potracelib.c potracelib.h lists.h auxiliary.h bitmap.h    \
# progress.h
#libpotrace_la_LDFLAGS = -version-info 0:0:0

#----------------------------------------------------------------------
# other stuff to distribute

EXTRA_DIST = getopt.c getopt1.c getopt.h

#----------------------------------------------------------------------
# The following dependencies were generated with
# makedepend -DHAVE_CONFIG_H -I.. -f- -Y *.c

# DO NOT DELETE

backend_eps.o: potracelib.h curve.h auxiliary.h ../config.h main.h
backend_eps.o: backend_eps.h flate.h lists.h
backend_gimp.o: main.h ../config.h potracelib.h backend_gimp.h lists.h
backend_gimp.o: auxiliary.h
backend_pdf.o: main.h ../config.h potracelib.h backend_pdf.h flate.h lists.h
backend_pdf.o: auxiliary.h
backend_pgm.o: backend_pgm.h potracelib.h main.h ../config.h lists.h
backend_pgm.o: greymap.h render.h auxiliary.h
backend_svg.o: potracelib.h curve.h auxiliary.h ../config.h main.h
backend_svg.o: backend_svg.h lists.h
backend_xfig.o: main.h ../config.h potracelib.h backend_xfig.h lists.h
backend_xfig.o: auxiliary.h
bitmap_io.o: bitmap.h ../config.h potracelib.h
curve.o: potracelib.h lists.h curve.h auxiliary.h ../config.h
decompose.o: potracelib.h curve.h auxiliary.h ../config.h lists.h bitmap.h
decompose.o: decompose.h progress.h
flate.o: ../config.h flate.h lzw.h
getopt1.o: ../config.h getopt.h
getopt.o: ../config.h getopt.h
greymap.o: greymap.h
lzw.o: lists.h bitops.h ../config.h lzw.h
main.o: getopt.h main.h ../config.h potracelib.h backend_pdf.h backend_eps.h
main.o: backend_pgm.h backend_svg.h backend_gimp.h backend_xfig.h bitmap_io.h
main.o: bitmap.h platform.h auxiliary.h
mkbitmap.o: getopt.h greymap.h bitmap_io.h bitmap.h ../config.h potracelib.h
mkbitmap.o: platform.h
potracelib.o: potracelib.h curve.h auxiliary.h ../config.h decompose.h
potracelib.o: progress.h trace.h
potracelib_demo.o: potracelib.h
render.o: render.h greymap.h auxiliary.h ../config.h potracelib.h
trace.o: potracelib.h curve.h auxiliary.h ../config.h lists.h trace.h
trace.o: progress.h
