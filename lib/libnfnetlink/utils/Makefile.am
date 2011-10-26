include $(top_srcdir)/Make_global.am

noinst_PROGRAMS = iftest

iftest_SOURCES = iftest.c
iftest_LDADD = ../src/libnfnetlink.la
iftest_LDFLAGS = -dynamic -ldl
