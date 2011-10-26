#
#  Makefile for the wb_group external_acl helper
#
#  $Id: Makefile.am,v 1.2.2.4 2003/05/16 14:35:48 hno Exp $
#

libexec_PROGRAMS = wb_group
wb_group_SOURCES = wb_check_group.c wb_common.c wbntlm.h wb_common.h
EXTRA_DIST = readme.txt
INCLUDES = -I. -I$(top_builddir)/include -I$(top_srcdir)/include \
    -I$(top_srcdir)/src -I@SAMBASOURCES@
LDADD = -L$(top_builddir)/lib $(XTRA_LIBS)
