SUBDIRS = raw2packet packet2flow

INCLUDES = $(all_includes) -I$(top_srcdir)/include

noinst_HEADERS = rtnl.h iftable.h

pkglib_LTLIBRARIES = ulogd_filter_IFINDEX.la ulogd_filter_PWSNIFF.la \
		     ulogd_filter_PRINTPKT.la ulogd_filter_PRINTFLOW.la

ulogd_filter_IFINDEX_la_SOURCES = ulogd_filter_IFINDEX.c rtnl.c iftable.c
ulogd_filter_IFINDEX_la_LDFLAGS = -module

ulogd_filter_PWSNIFF_la_SOURCES = ulogd_filter_PWSNIFF.c
ulogd_filter_PWSNIFF_la_LDFLAGS = -module

ulogd_filter_PRINTPKT_la_SOURCES = ulogd_filter_PRINTPKT.c ../util/printpkt.c
ulogd_filter_PRINTPKT_la_LDFLAGS = -module

ulogd_filter_PRINTFLOW_la_SOURCES = ulogd_filter_PRINTFLOW.c ../util/printflow.c
ulogd_filter_PRINTFLOW_la_LDFLAGS = -module
