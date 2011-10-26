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
AM_LDFLAGS = -no-install
LDADD = ../lib/libidn.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

TESTS = tst_stringprep tst_punycode tst_idna tst_idna2 tst_nfkc tst_pr29
if TLD
TESTS += tst_tld
endif
check_PROGRAMS = $(TESTS)

# Maintainer targets

indent:
	indent $(SOURCES)
