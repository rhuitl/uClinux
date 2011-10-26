# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool documentation before making any modification
LIBVERSION=2:0:1

INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_log.la libnetfilter_log_libipulog.la

libnetfilter_log_la_LDFLAGS = -Wc,-nostartfiles -lnfnetlink	\
			      -version-info $(LIBVERSION)
libnetfilter_log_la_SOURCES = libnetfilter_log.c 

libnetfilter_log_libipulog_la_LDFLAGS = -Wc,-nostartfiles	\
					-version-info 1:0:0
libnetfilter_log_libipulog_la_LIBADD = libnetfilter_log.la
libnetfilter_log_libipulog_la_SOURCES = libipulog_compat.c
