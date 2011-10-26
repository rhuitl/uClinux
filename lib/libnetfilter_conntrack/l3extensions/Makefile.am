include $(top_srcdir)/Make_global.am

AUTOMAKE_OPTIONS = no-dependencies foreign

AM_CFLAGS=-fPIC -Wall
LIBS=

pkglib_LTLIBRARIES = nfct_l3proto_ipv4.la nfct_l3proto_ipv6.la

nfct_l3proto_ipv4_la_SOURCES = libnetfilter_conntrack_ipv4.c 
nfct_l3proto_ipv4_la_LDFLAGS = -module -avoid-version -release $(VERSION)
nfct_l3proto_ipv4_la_LIBADD = ../src/libnetfilter_conntrack.la

nfct_l3proto_ipv6_la_SOURCES = libnetfilter_conntrack_ipv6.c
nfct_l3proto_ipv6_la_LDFLAGS = -module -avoid-version -release $(VERSION)
nfct_l3proto_ipv6_la_LIBADD = ../src/libnetfilter_conntrack.la
