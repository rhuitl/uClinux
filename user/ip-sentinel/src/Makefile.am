## $Id: Makefile.am,v 1.10 2005/03/29 02:09:17 ensc Exp $

# Copyright (C) 2002,2003,2004 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
#  
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#  
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#  

sbin_PROGRAMS			=  ip-sentinel

if ENSC_NEED_ETHER
ether_SRCS			=  ether.c
else
ether_SRCS			=
endif

lib_SRCS			=  arguments.c util.c blacklist.c 	\
				   antidos.c prioqueue.c worker.c	\
				   $(ether_SRCS)			\
				   $(ensc_fmt_SRCS)

EXTRA_ip_sentinel_SOURCES	=  ether.c
ip_sentinel_SOURCES		=  ip-sentinel.c $(lib_SRCS)
ip_sentinel_LDADD		=  $(LIBENSCVECTOR)

AM_CPPFLAGS			=  -D_GNU_SOURCE

noinst_HEADERS			=  antidos.h arguments.h arpmessage.h	\
				   blacklist.h compat.h ip-sentinel.h	\
				   parameters.h util.h			\
				   worker.h jobinfo.h			\
				   wrappers.h fmt.h			\
				   prioqueue.h prioqueue.ic		\
				   $(ENSC_VECTOR_HDRS) $(ENSC_VECTOR_XHDRS)

noinst_LIBRARIES		=  $(ENSC_VECTOR_LIBS)

EXTRA_DIST			=  $(testsuite_FILES)
CLEANFILES			=  $(testsuite_CLEANFILES)

check_PROGRAMS			=  $(ENSC_VECTOR_TESTSUITE_PRGS)
TESTS				=  $(ENSC_VECTOR_TESTSUITE_TSTS)



include $(top_srcdir)/m4/diet.am
include $(srcdir)/testsuite/Makefile-files
include $(srcdir)/ensc_vector/Makefile-files
include $(srcdir)/ensc_fmt/Makefile-files
include $(top_srcdir)/m4/libsel.am
