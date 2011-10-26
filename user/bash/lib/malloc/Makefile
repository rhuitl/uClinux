# Generated automatically from Makefile.in by configure.
# Skeleton Makefile for the GNU malloc code
#
#
# Copyright (C) 1996 Free Software Foundation, Inc.     

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 USA.

srcdir = .
VPATH = .:.
topdir = ../..
BUILD_DIR = $(ROOTDIR)/user/bash

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

#CC = 
#RANLIB = 
#AR = 
ARFLAGS = cr
RM = rm -f
CP = cp
MV = mv

SHELL = /bin/sh

PROFILE_FLAGS = 

CFLAGS +=  -I$(topdir)/lib/termcap
LOCAL_CFLAGS = 
#CPPFLAGS = 
LDFLAGS +=  -L./lib/termcap

DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL

BASHINCDIR = ${topdir}/include

INCLUDES = -I. -I../.. -I$(topdir) -I$(BASHINCDIR) -I$(topdir)/lib

CCFLAGS = ${PROFILE_FLAGS} ${INCLUDES} $(DEFS) $(LOCAL_DEFS) $(LOCAL_CFLAGS) \
	  $(CFLAGS) $(MALLOC_CFLAGS) $(CPPFLAGS)

.c.o:
	$(CC) $(CCFLAGS) -c $<

.s.o:
	$(CC) $(CCFLAGS) -c $<

MALLOC_SOURCE = malloc.c
GMALLOC_SOURCE = gmalloc.c
NMALLOC_SOURCE = nmalloc.c
STUB_SOURCE = stub.c

ALLOCA_SOURCE = alloca.c
ALLOCA_OBJECT = alloca.o

MALLOC_SRC = stub.c
MALLOC = @MALLOC@
ALLOCA = 

MALLOC_OBJS = malloc.o $(ALLOCA) stub.o
GMALLOC_OBJS = gmalloc.o $(ALLOCA) stub.o
NMALLOC_OBJS = nmalloc.o $(ALLOCA) stub.o
NMALLOC2_OBJS = nmalloc2.o $(ALLOCA) stub.o
NGMALLOC_OBJS = ngmalloc.o $(ALLOCA) stub.o
STUB_OBJS = $(ALLOCA) stub.o

.PHONY:		malloc gmalloc stubmalloc nmalloc ngmalloc nmalloc2

all:		malloc

malloc: ${MALLOC_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${MALLOC_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

nmalloc: ${NMALLOC_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${NMALLOC_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

nmalloc2: ${NMALLOC2_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${NMALLOC2_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

gmalloc: ${GMALLOC_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${GMALLOC_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

ngmalloc: ${NGMALLOC_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${NGMALLOC_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

stubmalloc: ${STUB_OBJS}
	${RM} libmalloc.a
	${AR} ${ARFLAGS} libmalloc.a ${STUB_OBJS}
	-test -n "$(RANLIB)" && $(RANLIB) libmalloc.a

alloca.o:	$(srcdir)/$(ALLOCA_SOURCE)
	$(CC) $(CCFLAGS) -c $(srcdir)/$(ALLOCA_SOURCE)
	@- if test "$(ALLOCA_OBJECT)" != alloca.o ; then \
		mv $(ALLOCA_OBJECT) alloca.o >/dev/null 2>&1 ; \
	fi

mostlyclean clean:
	$(RM) *.o libmalloc.a

distclean realclean maintainer-clean: clean
	$(RM) Makefile

alloca.o: $(BUILD_DIR)/config.h
malloc.o: $(BUILD_DIR)/config.h $(topdir)/bashtypes.h getpagesize.h
nmalloc.o: $(BUILD_DIR)/config.h $(topdir)/bashtypes.h getpagesize.h
nmalloc2.o: $(BUILD_DIR)/config.h $(topdir)/bashtypes.h getpagesize.h
xmalloc.o: $(BUILD_DIR)/config.h $(BASHINCDIR)/ansi_stdlib.h
gmalloc.o: $(BUILD_DIR)/config.h

# Rules for deficient makes, like SunOS and Solaris
stub.o: stub.c
malloc.o: malloc.c
gmalloc.o: gmalloc.c
