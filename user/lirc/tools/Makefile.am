## $Id: Makefile.am,v 5.5 2000/07/08 08:17:48 columbus Exp $

## Process this file with automake to produce Makefile.in 

EXTRA_PROGRAMS = smode2 xmode2 irxevent
bin_PROGRAMS = irw irpty irexec mode2 @vga_progs@ @x_progs@

## simple programs
irw_SOURCES = irw.c
irpty_SOURCES = irpty.c
irpty_DEPENDENCIES = liblirc_client.la
irpty_LDADD = liblirc_client.la
irexec_SOURCES = irexec.c
irexec_DEPENDENCIES = liblirc_client.la
irexec_LDADD = liblirc_client.la @daemon@
mode2_SOURCES = mode2.c

## vga programs
smode2_SOURCES = smode2.c
smode2_LDADD = -lvga -lvgagl

## x programs
irxevent_SOURCES = irxevent.c
irxevent_CFLAGS = @X_CFLAGS@
irxevent_LDADD = @X_LIBS@ @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@ liblirc_client.la
irxevent_DEPENDENCIES = liblirc_client.la
xmode2_SOURCES = xmode2.c
xmode2_CFLAGS = @X_CFLAGS@
xmode2_LDADD = @X_LIBS@ @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@

## libraries
lircincludedir = $(includedir)/lirc

lib_LTLIBRARIES = liblirc_client.la
liblirc_client_la_SOURCES = lirc_client.c lirc_client.h
lircinclude_HEADERS = lirc_client.h

CLEANFILES = *~
