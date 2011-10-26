## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
#
# This file is part of GNU Libidn.
#
# GNU Libidn is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU Libidn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU Libidn; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

AM_CPPFLAGS = -I$(top_srcdir)/lib -I../lib

dist_lisp_DATA = punycode.el idna.el

bin_PROGRAMS = idn

BUILT_SOURCES = idn_cmd.c idn_cmd.h $(GETOPT_H)
idn_SOURCES = idn.c gettext.h idn.ggo idn_cmd.c idn_cmd.h
EXTRA_DIST = getopt_.h getopt_int.h
DISTCLEANFILES = $(BUILT_SOURCES)
idn_LDADD = ../lib/libidn.la $(LTLIBINTL) $(LTLIBOBJS)

# We need the following in order to create an <getopt.h> when the system
# doesn't have one that works with the given compiler.
all-local $(idn_OBJECTS): $(GETOPT_H)
getopt.h: getopt_.h
	cp $(srcdir)/getopt_.h $@-t
	mv $@-t $@
MOSTLYCLEANFILES = getopt.h getopt.h-t

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

idn.c: $(BUILT_SOURCES)

idn_cmd.c idn_cmd.h: idn.ggo
	gengetopt --unamed-opts --input $^ --file-name idn_cmd || \
		test -f idn_cmd.h -a -f idn_cmd.c || \
		cp $(srcdir)/idn_cmd.h $(srcdir)/idn_cmd.h .
	perl -pi -e 's/\[FILES\]/\[STRINGS\]/g' idn_cmd.c

# Maintainer targets

indent:
	indent idn.c
