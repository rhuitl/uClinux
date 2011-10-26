# Generated automatically from Makefile.in by configure.
#
# Simple Makefile for the support programs.
#
# documentation support: man2html
# testing support: printenv recho zecho
#
# bashbug lives here but is created by the top-level makefile
#
# Currently only man2html is built
#
#
# Copyright (C) 1998 Free Software Foundation, Inc.     

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

#
# Boilerplate
#
topdir = ..
srcdir = .
VPATH = .:.
BUILD_DIR = $(ROOTDIR)/user/bash

RM	= rm -f
SHELL	= /bin/sh
#CC = 

EXEEXT = 

#
# Compiler options:
#
PROFILE_FLAGS = 
CFLAGS +=  -I$(topdir)/lib/termcap
LOCAL_CFLAGS = 
#CPPFLAGS = 
DEFS = -DHAVE_CONFIG_H
LOCAL_DEFS = -DSHELL
LDFLAGS +=  -L./lib/termcap $(LOCAL_LDFLAGS) $(CFLAGS)
LOCAL_LDFLAGS = -rdynamic
LIBS = $(LDLIBS)

INCLUDES = -I${BUILD_DIR} -I${topdir}

#
CCFLAGS = ${PROFILE_FLAGS} $(DEFS) $(LOCAL_DEFS) $(SYSTEM_FLAGS) $(CPPFLAGS) \
	  ${INCLUDES} $(LOCAL_CFLAGS) $(CFLAGS)

SRC1 =	man2html.c
OBJ1 =	man2html.o

.c.o:
	$(RM) $@
	$(CC) -c $(CCFLAGS) $<

all: man2html$(EXEEXT)

man2html$(EXEEXT): $(OBJ1)
	$(CC) $(CCFLAGS) $(OBJ1) -o $@ ${LIBS}

clean:
	rm man2html

man2html.o: man2html.c
