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

USRPGMS = aread awrite ttcp_atm
PGMS = align aping br bw isp window
bin_PROGRAMS = $(USRPGMS)
noinst_PROGRAMS = $(PGMS)

LDADD = $(top_builddir)/src/lib/libatm.la

aread_SOURCES = aread.c
awrite_SOURCES = awrite.c
ttcp_atm_SOURCES = ttcp.c

align_SOURCES = align.c
aping_SOURCES = aping.c
br_SOURCES = br.c
bw_SOURCES = bw.c
isp_SOURCES = isp.c isp.h ispl_y.y ispl_l.l
isp_XTRAS = $(LDADD)
isp_LDADD = $(isp_XTRAS) -lfl
isp_DEPENDENCIES = $(isp_XTRAS) errnos.inc
window_SOURCES = window.c

CLEANFILES = errnos.inc

EXTRA_DIST = ispl_y.h README.isp mkerrnos.pl
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../../config.h
CONFIG_CLEAN_FILES = 
PROGRAMS =  $(bin_PROGRAMS) $(noinst_PROGRAMS)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I../..
CPPFLAGS = 
LDFLAGS = 
LIBS = 
aread_OBJECTS =  aread.o
aread_LDADD = $(LDADD)
aread_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
aread_LDFLAGS = 
awrite_OBJECTS =  awrite.o
awrite_LDADD = $(LDADD)
awrite_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
awrite_LDFLAGS = 
ttcp_atm_OBJECTS =  ttcp.o
ttcp_atm_LDADD = $(LDADD)
ttcp_atm_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
ttcp_atm_LDFLAGS = 
align_OBJECTS =  align.o
align_LDADD = $(LDADD)
align_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
align_LDFLAGS = 
aping_OBJECTS =  aping.o
aping_LDADD = $(LDADD)
aping_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
aping_LDFLAGS = 
br_OBJECTS =  br.o
br_LDADD = $(LDADD)
br_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
br_LDFLAGS = 
bw_OBJECTS =  bw.o
bw_LDADD = $(LDADD)
bw_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
bw_LDFLAGS = 
isp_OBJECTS =  isp.o ispl_y.o ispl_l.o
isp_LDFLAGS = 
window_OBJECTS =  window.o
window_LDADD = $(LDADD)
window_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
window_LDFLAGS = 
LEX_OUTPUT_ROOT = lex.yy
LEXLIB = -lfl
CFLAGS = -I$(top_srcdir)/src/include -g -O2 -Wall -Wshadow -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
DIST_COMMON =  Makefile.am Makefile.in ispl_l.c ispl_y.c


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = gtar
GZIP_ENV = --best
SOURCES = $(aread_SOURCES) $(awrite_SOURCES) $(ttcp_atm_SOURCES) $(align_SOURCES) $(aping_SOURCES) $(br_SOURCES) $(bw_SOURCES) $(isp_SOURCES) $(window_SOURCES)
OBJECTS = $(aread_OBJECTS) $(awrite_OBJECTS) $(ttcp_atm_OBJECTS) $(align_OBJECTS) $(aping_OBJECTS) $(br_OBJECTS) $(bw_OBJECTS) $(isp_OBJECTS) $(window_OBJECTS)

all: all-redirect
.SUFFIXES:
.SUFFIXES: .S .c .l .lo .o .s .y
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4) 
	cd $(top_srcdir) && $(AUTOMAKE) --gnu --include-deps src/test/Makefile

Makefile: $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status


mostlyclean-binPROGRAMS:

clean-binPROGRAMS:
	-test -z "$(bin_PROGRAMS)" || rm -f $(bin_PROGRAMS)

distclean-binPROGRAMS:

maintainer-clean-binPROGRAMS:

install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo " $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`"; \
	    $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	  else :; fi; \
	done

uninstall-binPROGRAMS:
	@$(NORMAL_UNINSTALL)
	list='$(bin_PROGRAMS)'; for p in $$list; do \
	  rm -f $(DESTDIR)$(bindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	done

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

aread: $(aread_OBJECTS) $(aread_DEPENDENCIES)
	@rm -f aread
	$(LINK) $(aread_LDFLAGS) $(aread_OBJECTS) $(aread_LDADD) $(LIBS)

awrite: $(awrite_OBJECTS) $(awrite_DEPENDENCIES)
	@rm -f awrite
	$(LINK) $(awrite_LDFLAGS) $(awrite_OBJECTS) $(awrite_LDADD) $(LIBS)

ttcp_atm: $(ttcp_atm_OBJECTS) $(ttcp_atm_DEPENDENCIES)
	@rm -f ttcp_atm
	$(LINK) $(ttcp_atm_LDFLAGS) $(ttcp_atm_OBJECTS) $(ttcp_atm_LDADD) $(LIBS)

align: $(align_OBJECTS) $(align_DEPENDENCIES)
	@rm -f align
	$(LINK) $(align_LDFLAGS) $(align_OBJECTS) $(align_LDADD) $(LIBS)

aping: $(aping_OBJECTS) $(aping_DEPENDENCIES)
	@rm -f aping
	$(LINK) $(aping_LDFLAGS) $(aping_OBJECTS) $(aping_LDADD) $(LIBS)

br: $(br_OBJECTS) $(br_DEPENDENCIES)
	@rm -f br
	$(LINK) $(br_LDFLAGS) $(br_OBJECTS) $(br_LDADD) $(LIBS)

bw: $(bw_OBJECTS) $(bw_DEPENDENCIES)
	@rm -f bw
	$(LINK) $(bw_LDFLAGS) $(bw_OBJECTS) $(bw_LDADD) $(LIBS)

isp: $(isp_OBJECTS) $(isp_DEPENDENCIES)
	@rm -f isp
	$(LINK) $(isp_LDFLAGS) $(isp_OBJECTS) $(isp_LDADD) $(LIBS)

window: $(window_OBJECTS) $(window_DEPENDENCIES)
	@rm -f window
	$(LINK) $(window_LDFLAGS) $(window_OBJECTS) $(window_LDADD) $(LIBS)
.l.c:
	$(LEX) $(AM_LFLAGS) $(LFLAGS) $< && mv $(LEX_OUTPUT_ROOT).c $@
.y.c:
	$(YACC) $(AM_YFLAGS) $(YFLAGS) $< && mv y.tab.c $*.c
	if test -f y.tab.h; then \
	if cmp -s y.tab.h $*.h; then rm -f y.tab.h; else mv y.tab.h $*.h; fi; \
	else :; fi
ispl_y.h: ispl_y.c


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

subdir = src/test

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
check: check-am
installcheck-am:
installcheck: installcheck-am
install-exec-am: install-binPROGRAMS
install-exec: install-exec-am

install-data-am:
install-data: install-data-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
install: install-am
uninstall-am: uninstall-binPROGRAMS
uninstall: uninstall-am
all-am: Makefile $(PROGRAMS)
all-redirect: all-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) AM_INSTALL_PROGRAM_FLAGS=-s install
installdirs:
	$(mkinstalldirs)  $(DESTDIR)$(bindir)


mostlyclean-generic:

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*

maintainer-clean-generic:
	-test -z "ispl_llispl_yhispl_yc" || rm -f ispl_ll ispl_yh ispl_yc
mostlyclean-am:  mostlyclean-binPROGRAMS mostlyclean-noinstPROGRAMS \
		mostlyclean-compile mostlyclean-libtool \
		mostlyclean-tags mostlyclean-generic

mostlyclean: mostlyclean-am

clean-am:  clean-binPROGRAMS clean-noinstPROGRAMS clean-compile \
		clean-libtool clean-tags clean-generic mostlyclean-am

clean: clean-am

distclean-am:  distclean-binPROGRAMS distclean-noinstPROGRAMS \
		distclean-compile distclean-libtool distclean-tags \
		distclean-generic clean-am
	-rm -f libtool

distclean: distclean-am

maintainer-clean-am:  maintainer-clean-binPROGRAMS \
		maintainer-clean-noinstPROGRAMS \
		maintainer-clean-compile maintainer-clean-libtool \
		maintainer-clean-tags maintainer-clean-generic \
		distclean-am
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

maintainer-clean: maintainer-clean-am

.PHONY: mostlyclean-binPROGRAMS distclean-binPROGRAMS clean-binPROGRAMS \
maintainer-clean-binPROGRAMS uninstall-binPROGRAMS install-binPROGRAMS \
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


isp.o: errnos.inc

errnos.inc: mkerrnos.pl
	/usr/bin/perl ./mkerrnos.pl </usr/include/asm/errno.h \
		>errnos.inc || { rm -f errnos.inc; exit 1; }

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
