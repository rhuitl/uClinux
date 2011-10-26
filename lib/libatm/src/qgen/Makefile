# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.4 from Makefile.am

# Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.


SHELL = /bin/sh

srcdir = .
top_srcdir = ../..
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

DESTDIR =

pkgdatadir = $(datadir)/linux-atm
pkglibdir = $(libdir)/linux-atm
pkgincludedir = $(includedir)/linux-atm

top_builddir = ../..

ACLOCAL = aclocal
AUTOCONF = autoconf
AUTOMAKE = automake
AUTOHEADER = autoheader

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL} $(AM_INSTALL_PROGRAM_FLAGS)
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,

NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_alias = i686-pc-linux
build_triplet = i686-pc-linux-gnu
host_alias = i686-pc-linux
host_triplet = i686-pc-linux-gnu
target_alias = i686-pc-linux
target_triplet = i686-pc-linux-gnu
AS = @AS@
CC = gcc
DLLTOOL = @DLLTOOL@
LEX = flex
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBTOOL_DEPS = ./ltconfig ./ltmain.sh
LIBVER_AGE = 0
LIBVER_CURRENT = 1
LIBVER_REVISION = 0
LN_S = ln -s
MAKEINFO = makeinfo
OBJDUMP = @OBJDUMP@
PACKAGE = linux-atm
PERL = /usr/bin/perl
RANLIB = ranlib
VERSION = 2.4.0
YACC = bison -y -d

noinst_PROGRAMS = qgen q.dump # q40.out.o
check_PROGRAMS = q.test

qgen_SOURCES = common.c common.h file.c file.h first.c ql_y.y ql_l.l qgen.c 		qgen.h second.c third.c

qgen_LDADD = -lfl

q_dump_SOURCES = common.c
q_dump_LDADD = qd.dump.standalone.o
# FIXME: paulsch: We don't really depend on qd.dump.o or q.out.o here, but this
# trick will get it built with only a minor glitch in the dependency checking
# for q.dump.
q_dump_DEPENDENCIES = $(q_dump_LDADD) qd.dump.o q.out.o
EXTRA_q_dump_SOURCES = op.h uni.h qlib.c qlib.h

q_test_SOURCES = qtest.c uni.h
q_test_DEPENDENCIES = q.test.c

#TESTS = $(check_PROGRAMS)

EXTRA_DIST = ql_y.h incl.pl mknl.pl msg.fmt TODO

CLEANFILES = q.out.h q.out.c q.test.c qd.out.h qd.out.c qd.dump.c qd.test.c 		default.nl # q40.out.h q40.out.c q40.test.c


NLS = atm_ai_msg atm_ai_ie atm_loc atm_cv atm_pu atm_na atm_cond atm_ie 	atm_msg atm_np atm_ton atm_sat atm_prs atm_scrn atm_vpa atm_poe 	q2931_cs atm_td atm_bc atm_tc atm_stc atm_upcc q2931_proto atm_flag 	atm_aalp atm_fd atm_tag atm_l2 atm_l3 atm_tt atm_mc atm_hl atm_imd 	atm_tdl atm_tni atm_nip atm_shi atm_oci atm_unfm atm_ofi atm_irs 	atm_it atm_lit atm_lsi atm_tcs atm_css atm_eqo atm_eqp atm_aap 	atm_asp atm_tor

SYMFILES = uni.h $(shell /usr/bin/perl incl.pl $(CFLAGS) linux/atmsap.h)
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../../config.h
CONFIG_CLEAN_FILES = 
PROGRAMS =  $(noinst_PROGRAMS)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I../..
CPPFLAGS = 
LDFLAGS = 
LIBS = 
q_test_OBJECTS =  qtest.o
q_test_LDADD = $(LDADD)
q_test_LDFLAGS = 
qgen_OBJECTS =  common.o file.o first.o ql_y.o ql_l.o qgen.o second.o \
third.o
qgen_DEPENDENCIES = 
qgen_LDFLAGS = 
q_dump_OBJECTS =  common.o
q_dump_LDFLAGS = 
LEX_OUTPUT_ROOT = lex.yy
LEXLIB = -lfl
CFLAGS = -I$(top_srcdir)/src/include -g -O2 -Wall -Wshadow -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
DIST_COMMON =  Makefile.am Makefile.in TODO ql_l.c ql_y.c


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = gtar
GZIP_ENV = --best
SOURCES = $(q_test_SOURCES) $(qgen_SOURCES) $(q_dump_SOURCES) $(EXTRA_q_dump_SOURCES)
OBJECTS = $(q_test_OBJECTS) $(qgen_OBJECTS) $(q_dump_OBJECTS)

all: all-redirect
.SUFFIXES:
.SUFFIXES: .S .c .l .lo .o .s .y
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4) 
	cd $(top_srcdir) && $(AUTOMAKE) --gnu --include-deps src/qgen/Makefile

Makefile: $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status


mostlyclean-checkPROGRAMS:

clean-checkPROGRAMS:
	-test -z "$(check_PROGRAMS)" || rm -f $(check_PROGRAMS)

distclean-checkPROGRAMS:

maintainer-clean-checkPROGRAMS:

mostlyclean-noinstPROGRAMS:

clean-noinstPROGRAMS:
	-test -z "$(noinst_PROGRAMS)" || rm -f $(noinst_PROGRAMS)

distclean-noinstPROGRAMS:

maintainer-clean-noinstPROGRAMS:

.c.o:
	$(COMPILE) -c $<

.s.o:
	$(COMPILE) -c $<

.S.o:
	$(COMPILE) -c $<

mostlyclean-compile:
	-rm -f *.o core *.core

clean-compile:

distclean-compile:
	-rm -f *.tab.c

maintainer-clean-compile:

.c.lo:
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

.s.lo:
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

.S.lo:
	$(LIBTOOL) --mode=compile $(COMPILE) -c $<

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

distclean-libtool:

maintainer-clean-libtool:

q.test: $(q_test_OBJECTS) $(q_test_DEPENDENCIES)
	@rm -f q.test
	$(LINK) $(q_test_LDFLAGS) $(q_test_OBJECTS) $(q_test_LDADD) $(LIBS)

qgen: $(qgen_OBJECTS) $(qgen_DEPENDENCIES)
	@rm -f qgen
	$(LINK) $(qgen_LDFLAGS) $(qgen_OBJECTS) $(qgen_LDADD) $(LIBS)

q.dump: $(q_dump_OBJECTS) $(q_dump_DEPENDENCIES)
	@rm -f q.dump
	$(LINK) $(q_dump_LDFLAGS) $(q_dump_OBJECTS) $(q_dump_LDADD) $(LIBS)
.l.c:
	$(LEX) $(AM_LFLAGS) $(LFLAGS) $< && mv $(LEX_OUTPUT_ROOT).c $@
.y.c:
	$(YACC) $(AM_YFLAGS) $(YFLAGS) $< && mv y.tab.c $*.c
	if test -f y.tab.h; then \
	if cmp -s y.tab.h $*.h; then rm -f y.tab.h; else mv y.tab.h $*.h; fi; \
	else :; fi
ql_y.h: ql_y.c


tags: TAGS

ID: $(HEADERS) $(SOURCES) $(LISP)
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	here=`pwd` && cd $(srcdir) \
	  && mkid -f$$here/ID $$unique $(LISP)

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(ETAGS_ARGS)$$unique$(LISP)$$tags" \
	  || (cd $(srcdir) && etags $(ETAGS_ARGS) $$tags  $$unique $(LISP) -o $$here/TAGS)

mostlyclean-tags:

clean-tags:

distclean-tags:
	-rm -f TAGS ID

maintainer-clean-tags:

distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)

subdir = src/qgen

distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  if test -d $$d/$$file; then \
	    cp -pr $$d/$$file $(distdir)/$$file; \
	  else \
	    test -f $(distdir)/$$file \
	    || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	    || cp -p $$d/$$file $(distdir)/$$file || :; \
	  fi; \
	done

info-am:
info: info-am
dvi-am:
dvi: dvi-am
check-am: all-am
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS)
check: check-am
installcheck-am:
installcheck: installcheck-am
install-exec-am:
install-exec: install-exec-am

install-data-am:
install-data: install-data-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
install: install-am
uninstall-am:
uninstall: uninstall-am
all-am: Makefile $(PROGRAMS)
all-redirect: all-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) AM_INSTALL_PROGRAM_FLAGS=-s install
installdirs:


mostlyclean-generic:

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*

maintainer-clean-generic:
	-test -z "ql_llql_yhql_yc" || rm -f ql_ll ql_yh ql_yc
mostlyclean-am:  mostlyclean-checkPROGRAMS mostlyclean-noinstPROGRAMS \
		mostlyclean-compile mostlyclean-libtool \
		mostlyclean-tags mostlyclean-generic

mostlyclean: mostlyclean-am

clean-am:  clean-checkPROGRAMS clean-noinstPROGRAMS clean-compile \
		clean-libtool clean-tags clean-generic mostlyclean-am

clean: clean-am

distclean-am:  distclean-checkPROGRAMS distclean-noinstPROGRAMS \
		distclean-compile distclean-libtool distclean-tags \
		distclean-generic clean-am
	-rm -f libtool

distclean: distclean-am

maintainer-clean-am:  maintainer-clean-checkPROGRAMS \
		maintainer-clean-noinstPROGRAMS \
		maintainer-clean-compile maintainer-clean-libtool \
		maintainer-clean-tags maintainer-clean-generic \
		distclean-am
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

maintainer-clean: maintainer-clean-am

.PHONY: mostlyclean-checkPROGRAMS distclean-checkPROGRAMS \
clean-checkPROGRAMS maintainer-clean-checkPROGRAMS \
mostlyclean-noinstPROGRAMS distclean-noinstPROGRAMS \
clean-noinstPROGRAMS maintainer-clean-noinstPROGRAMS \
mostlyclean-compile distclean-compile clean-compile \
maintainer-clean-compile mostlyclean-libtool distclean-libtool \
clean-libtool maintainer-clean-libtool tags mostlyclean-tags \
distclean-tags clean-tags maintainer-clean-tags distdir info-am info \
dvi-am dvi check check-am installcheck-am installcheck install-exec-am \
install-exec install-data-am install-data install-am install \
uninstall-am uninstall all-redirect all-am all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


default.nl: mknl.pl $(SYMFILES)
	cat $(SYMFILES) | /usr/bin/perl mknl.pl $(NLS) >default.nl || \
	{ rm -f default.nl; echo 1; }

q.out.h q.out.c q.test.c: qgen msg.fmt default.nl
	$(CPP) $(DEFS) - <msg.fmt | ./qgen

#q40.out.h q40.out.c q40.test.c: qgen uni40 default.nl
#	$(CPP) $(DEFS) - <uni40 | PREFIX=q40 ./qgen

qd.out.h qd.out.c qd.dump.c: qgen msg.fmt default.nl
	$(CPP) $(DEFS) - <msg.fmt | ./qgen -D

q.out.o: q.out.c q.out.h qlib.c qlib.h
	$(CC) $(DEFS) $(CFLAGS) -c q.out.c

#q40.out.o: q40.out.c q40.out.h qlib.c qlib.h
#	$(CC) -DUNI40 $(CFLAGS) -c q40.out.c

qd.dump.o: qd.dump.c qd.out.c qlib.c qlib.h
	$(CC) $(DEFS) $(CFLAGS) -c qd.dump.c

qd.dump.standalone.o: qd.dump.c qd.out.c qlib.c qlib.h
	$(CC) $(DEFS) -DSTANDALONE $(CFLAGS) -c qd.dump.c \
	-o qd.dump.standalone.o

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
