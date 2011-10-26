# Makefile for uClibc pwd_grp
#
# Copyright (C) 2000 by Lineo, inc.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Library General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Library General Public License for more
# details.
#
# You should have received a copy of the GNU Library General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# Derived in part from the Linux-8086 C library, the GNU C Library, and several
# other sundry sources.  Files within this library are copyright by their
# respective copyright holders.




# Set the following to `true' to make a debuggable build.
# Leave this set to `false' for production use.
# eg: `make DODEBUG=true'
DODEBUG = false

# If you are running a cross compiler, you may want to set this
# to something more interesting...
#CROSS = #powerpc-linux-
CC = $(CROSS)gcc
STRIPTOOL = $(CROSS)strip

# To compile vs an alternative libc, you may need to use/adjust
# the following lines to meet your needs.  This is how I make
# tinylogin compile with uC-Libc...
#LIBCDIR=/home/andersen/CVS/uClibc
#GCCINCDIR = $(shell gcc -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp")
#CFLAGS+=-nostdinc -I$(LIBCDIR)/include -I$(GCCINCDIR)
#LDFLAGS+=-nostdlib
#LIBRARIES = $(LIBCDIR)/libc.a -lgcc


#--------------------------------------------------------


# use '-Os' optimization if available, else use -O2
OPTIMIZATION = $(shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
    then echo "-Os"; else echo "-O2" ; fi)
WARNINGS = -Wall

ifeq ($(DODEBUG),true)
    CFLAGS  += $(WARNINGS) -g -D__LIBC__
    LDFLAGS += -Wl,-warn-common 
    STRIP    =
else
    CFLAGS  += $(WARNINGS) $(OPTIMIZATION) -fomit-frame-pointer -D__LIBC__
    LDFLAGS += -s -Wl,-warn-common 
    STRIP    = $(STRIPTOOL) --remove-section=.note --remove-section=.comment $(PROG)
endif


LIBPWD=libpwd.a

CSRC=__tlg_getpwent.c pwent.c getpwnam.c getpwuid.c putpwent.c getpw.c \
	fgetpwent.c __tlg_getgrent.c grent.c getgrnam.c getgrgid.c fgetgrent.c \
	initgroups.c setgroups.c
COBJS=$(patsubst %.c,%.o, $(CSRC))
OBJS=$(COBJS)

all: $(OBJS) $(LIBPWD)

$(LIBPWD): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBPWD) $(OBJS)

$(COBJS):
	$(CC) $(CFLAGS) $< -c $*.c -o $*.o
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

__tlg_getgrent.c: config.h
initgroups.c: config.h

clean:
	rm -f *.[oa] *~ core
