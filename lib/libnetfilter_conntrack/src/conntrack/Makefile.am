include $(top_srcdir)/Make_global.am

#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

AM_CFLAGS = -fPIC -Wall
LIBS = @LIBNFCONNTRACK_LIBS@

noinst_LTLIBRARIES = libnetfilter_conntrack_new_api.la 

libnetfilter_conntrack_new_api_la_SOURCES = api.c callback.c \
					    getter.c setter.c \
					    parse.c build.c \
					    snprintf.c \
					    snprintf_default.c snprintf_xml.c \
					    objopt.c \
					    compare.c
