
INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall

pkglib_LTLIBRARIES = ulogd_inpflow_NFCT.la # ulogd_inpflow_IPFIX.la

ulogd_inpflow_NFCT_la_SOURCES = ulogd_inpflow_NFCT.c
ulogd_inpflow_NFCT_la_LDFLAGS = -module -lnetfilter_conntrack -lnfnetlink

#ulogd_inpflow_IPFIX_la_SOURCES = ulogd_inpflow_IPFIX.c
#ulogd_inpflow_IPFIX_la_LDFLAGS = -module
