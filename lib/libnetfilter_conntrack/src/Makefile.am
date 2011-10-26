include $(top_srcdir)/Make_global.am

#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

SUBDIRS=conntrack expect

AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

lib_LTLIBRARIES = libnetfilter_conntrack.la 

libnetfilter_conntrack_la_LIBADD = conntrack/libnetfilter_conntrack_new_api.la \
				   expect/libnetfilter_conntrack_expect.la
libnetfilter_conntrack_la_LDFLAGS = -Wc,-nostartfiles -lnfnetlink -ldl 	\
				    -version-info $(LIBVERSION)
libnetfilter_conntrack_la_SOURCES = libnetfilter_conntrack.c 
