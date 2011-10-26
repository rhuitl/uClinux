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
# RCSID $Id: Makefile,v 1.3 2002/01/05 01:59:04 mcr Exp $

TOPDIR=../..
include $(TOPDIR)/Makefile.inc

SUBDIRS=

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	./dotests.sh

install checkprograms programs:

clean:
	cat TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT;\
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

