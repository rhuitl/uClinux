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

BOOTPGMS = atmaddr esi
SYSPGMS = atmloop atmtcp enitune zntune # nstune
USRPGMS = atmdiag atmdump sonetdiag saaldump

INCLUDES = -I$(top_builddir)/src/qgen -I$(top_builddir)/src/saal -I.
LDADD = $(top_builddir)/src/lib/libatm.la

sbin_PROGRAMS = $(BOOTPGMS) $(SYSPGMS)
bin_PROGRAMS = $(USRPGMS)

atmaddr_SOURCES = atmaddr.c
esi_SOURCES = esi.c

atmloop_SOURCES = atmloop.c
atmtcp_SOURCES = atmtcp.c
enitune_SOURCES = enitune.c
zntune_SOURCES = zntune.c
#nstune_SOURCES = nstune.c

atmdiag_SOURCES = atmdiag.c
atmdump_SOURCES = atmdump.c
sonetdiag_SOURCES = sonetdiag.c
saaldump_SOURCES = saaldump.c
saaldump_LDADD = $(top_builddir)/src/qgen/qd.dump.o $(top_builddir)/src/saal/libsaal.a $(LDADD)
saaldump_DEPENDENCIES = $(saaldump_LDADD)

man_MANS = atmaddr.8 atmdiag.8 atmdump.8 atmloop.8 atmtcp.8 esi.8

#EXTRA_DIST = $(man_MANS) README.nstune
EXTRA_DIST = $(man_MANS) README.nstune nstune.c
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = ../../config.h
CONFIG_CLEAN_FILES = 
PROGRAMS =  $(bin_PROGRAMS) $(sbin_PROGRAMS)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I../..
CPPFLAGS = 
LDFLAGS = 
LIBS = 
atmdiag_OBJECTS =  atmdiag.o
atmdiag_LDADD = $(LDADD)
atmdiag_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
atmdiag_LDFLAGS = 
atmdump_OBJECTS =  atmdump.o
atmdump_LDADD = $(LDADD)
atmdump_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
atmdump_LDFLAGS = 
sonetdiag_OBJECTS =  sonetdiag.o
sonetdiag_LDADD = $(LDADD)
sonetdiag_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
sonetdiag_LDFLAGS = 
saaldump_OBJECTS =  saaldump.o
saaldump_LDFLAGS = 
atmaddr_OBJECTS =  atmaddr.o
atmaddr_LDADD = $(LDADD)
atmaddr_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
atmaddr_LDFLAGS = 
esi_OBJECTS =  esi.o
esi_LDADD = $(LDADD)
esi_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
esi_LDFLAGS = 
atmloop_OBJECTS =  atmloop.o
atmloop_LDADD = $(LDADD)
atmloop_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
atmloop_LDFLAGS = 
atmtcp_OBJECTS =  atmtcp.o
atmtcp_LDADD = $(LDADD)
atmtcp_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
atmtcp_LDFLAGS = 
enitune_OBJECTS =  enitune.o
enitune_LDADD = $(LDADD)
enitune_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
enitune_LDFLAGS = 
zntune_OBJECTS =  zntune.o
zntune_LDADD = $(LDADD)
zntune_DEPENDENCIES =  $(top_builddir)/src/lib/libatm.la
zntune_LDFLAGS = 
CFLAGS = -I$(top_srcdir)/src/include -g -O2 -Wall -Wshadow -Wpointer-arith -Wwrite-strings -Wstrict-prototypes
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) --mode=compile $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(LIBTOOL) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
man8dir = $(mandir)/man8
MANS = $(man_MANS)

NROFF = nroff
DIST_COMMON =  Makefile.am Makefile.in


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = gtar
GZIP_ENV = --best
SOURCES = $(atmdiag_SOURCES) $(atmdump_SOURCES) $(sonetdiag_SOURCES) $(saaldump_SOURCES) $(atmaddr_SOURCES) $(esi_SOURCES) $(atmloop_SOURCES) $(atmtcp_SOURCES) $(enitune_SOURCES) $(zntune_SOURCES)
OBJECTS = $(atmdiag_OBJECTS) $(atmdump_OBJECTS) $(sonetdiag_OBJECTS) $(saaldump_OBJECTS) $(atmaddr_OBJECTS) $(esi_OBJECTS) $(atmloop_OBJECTS) $(atmtcp_OBJECTS) $(enitune_OBJECTS) $(zntune_OBJECTS)

all: all-redirect
.SUFFIXES:
.SUFFIXES: .S .c .lo .o .s
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4) 
	cd $(top_srcdir) && $(AUTOMAKE) --gnu --include-deps src/maint/Makefile

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

mostlyclean-sbinPROGRAMS:

clean-sbinPROGRAMS:
	-test -z "$(sbin_PROGRAMS)" || rm -f $(sbin_PROGRAMS)

distclean-sbinPROGRAMS:

maintainer-clean-sbinPROGRAMS:

install-sbinPROGRAMS: $(sbin_PROGRAMS)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sbindir)
	@list='$(sbin_PROGRAMS)'; for p in $$list; do \
	  if test -f $$p; then \
	    echo " $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(DESTDIR)$(sbindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`"; \
	    $(LIBTOOL)  --mode=install $(INSTALL_PROGRAM) $$p $(DESTDIR)$(sbindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	  else :; fi; \
	done

uninstall-sbinPROGRAMS:
	@$(NORMAL_UNINSTALL)
	list='$(sbin_PROGRAMS)'; for p in $$list; do \
	  rm -f $(DESTDIR)$(sbindir)/`echo $$p|sed 's/$(EXEEXT)$$//'|sed '$(transform)'|sed 's/$$/$(EXEEXT)/'`; \
	done

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

atmdiag: $(atmdiag_OBJECTS) $(atmdiag_DEPENDENCIES)
	@rm -f atmdiag
	$(LINK) $(atmdiag_LDFLAGS) $(atmdiag_OBJECTS) $(atmdiag_LDADD) $(LIBS)

atmdump: $(atmdump_OBJECTS) $(atmdump_DEPENDENCIES)
	@rm -f atmdump
	$(LINK) $(atmdump_LDFLAGS) $(atmdump_OBJECTS) $(atmdump_LDADD) $(LIBS)

sonetdiag: $(sonetdiag_OBJECTS) $(sonetdiag_DEPENDENCIES)
	@rm -f sonetdiag
	$(LINK) $(sonetdiag_LDFLAGS) $(sonetdiag_OBJECTS) $(sonetdiag_LDADD) $(LIBS)

saaldump: $(saaldump_OBJECTS) $(saaldump_DEPENDENCIES)
	@rm -f saaldump
	$(LINK) $(saaldump_LDFLAGS) $(saaldump_OBJECTS) $(saaldump_LDADD) $(LIBS)

atmaddr: $(atmaddr_OBJECTS) $(atmaddr_DEPENDENCIES)
	@rm -f atmaddr
	$(LINK) $(atmaddr_LDFLAGS) $(atmaddr_OBJECTS) $(atmaddr_LDADD) $(LIBS)

esi: $(esi_OBJECTS) $(esi_DEPENDENCIES)
	@rm -f esi
	$(LINK) $(esi_LDFLAGS) $(esi_OBJECTS) $(esi_LDADD) $(LIBS)

atmloop: $(atmloop_OBJECTS) $(atmloop_DEPENDENCIES)
	@rm -f atmloop
	$(LINK) $(atmloop_LDFLAGS) $(atmloop_OBJECTS) $(atmloop_LDADD) $(LIBS)

atmtcp: $(atmtcp_OBJECTS) $(atmtcp_DEPENDENCIES)
	@rm -f atmtcp
	$(LINK) $(atmtcp_LDFLAGS) $(atmtcp_OBJECTS) $(atmtcp_LDADD) $(LIBS)

enitune: $(enitune_OBJECTS) $(enitune_DEPENDENCIES)
	@rm -f enitune
	$(LINK) $(enitune_LDFLAGS) $(enitune_OBJECTS) $(enitune_LDADD) $(LIBS)

zntune: $(zntune_OBJECTS) $(zntune_DEPENDENCIES)
	@rm -f zntune
	$(LINK) $(zntune_LDFLAGS) $(zntune_OBJECTS) $(zntune_LDADD) $(LIBS)

install-man8:
	$(mkinstalldirs) $(DESTDIR)$(man8dir)
	@list='$(man8_MANS)'; \
	l2='$(man_MANS)'; for i in $$l2; do \
	  case "$$i" in \
	    *.8*) list="$$list $$i" ;; \
	  esac; \
	done; \
	for i in $$list; do \
	  if test -f $(srcdir)/$$i; then file=$(srcdir)/$$i; \
	  else file=$$i; fi; \
	  ext=`echo $$i | sed -e 's/^.*\\.//'`; \
	  inst=`echo $$i | sed -e 's/\\.[0-9a-z]*$$//'`; \
	  inst=`echo $$inst | sed '$(transform)'`.$$ext; \
	  echo " $(INSTALL_DATA) $$file $(DESTDIR)$(man8dir)/$$inst"; \
	  $(INSTALL_DATA) $$file $(DESTDIR)$(man8dir)/$$inst; \
	done

uninstall-man8:
	@list='$(man8_MANS)'; \
	l2='$(man_MANS)'; for i in $$l2; do \
	  case "$$i" in \
	    *.8*) list="$$list $$i" ;; \
	  esac; \
	done; \
	for i in $$list; do \
	  ext=`echo $$i | sed -e 's/^.*\\.//'`; \
	  inst=`echo $$i | sed -e 's/\\.[0-9a-z]*$$//'`; \
	  inst=`echo $$inst | sed '$(transform)'`.$$ext; \
	  echo " rm -f $(DESTDIR)$(man8dir)/$$inst"; \
	  rm -f $(DESTDIR)$(man8dir)/$$inst; \
	done
install-man: $(MANS)
	@$(NORMAL_INSTALL)
	$(MAKE) $(AM_MAKEFLAGS) install-man8
uninstall-man:
	@$(NORMAL_UNINSTALL)
	$(MAKE) $(AM_MAKEFLAGS) uninstall-man8

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

subdir = src/maint

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
install-exec-am: install-binPROGRAMS install-sbinPROGRAMS
install-exec: install-exec-am

install-data-am: install-man
install-data: install-data-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
install: install-am
uninstall-am: uninstall-binPROGRAMS uninstall-sbinPROGRAMS uninstall-man
uninstall: uninstall-am
all-am: Makefile $(PROGRAMS) $(MANS)
all-redirect: all-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) AM_INSTALL_PROGRAM_FLAGS=-s install
installdirs:
	$(mkinstalldirs)  $(DESTDIR)$(bindir) $(DESTDIR)$(sbindir) \
		$(DESTDIR)$(mandir)/man8


mostlyclean-generic:

clean-generic:

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*

maintainer-clean-generic:
mostlyclean-am:  mostlyclean-binPROGRAMS mostlyclean-sbinPROGRAMS \
		mostlyclean-compile mostlyclean-libtool \
		mostlyclean-tags mostlyclean-generic

mostlyclean: mostlyclean-am

clean-am:  clean-binPROGRAMS clean-sbinPROGRAMS clean-compile \
		clean-libtool clean-tags clean-generic mostlyclean-am

clean: clean-am

distclean-am:  distclean-binPROGRAMS distclean-sbinPROGRAMS \
		distclean-compile distclean-libtool distclean-tags \
		distclean-generic clean-am
	-rm -f libtool

distclean: distclean-am

maintainer-clean-am:  maintainer-clean-binPROGRAMS \
		maintainer-clean-sbinPROGRAMS maintainer-clean-compile \
		maintainer-clean-libtool maintainer-clean-tags \
		maintainer-clean-generic distclean-am
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

maintainer-clean: maintainer-clean-am

.PHONY: mostlyclean-binPROGRAMS distclean-binPROGRAMS clean-binPROGRAMS \
maintainer-clean-binPROGRAMS uninstall-binPROGRAMS install-binPROGRAMS \
mostlyclean-sbinPROGRAMS distclean-sbinPROGRAMS clean-sbinPROGRAMS \
maintainer-clean-sbinPROGRAMS uninstall-sbinPROGRAMS \
install-sbinPROGRAMS mostlyclean-compile distclean-compile \
clean-compile maintainer-clean-compile mostlyclean-libtool \
distclean-libtool clean-libtool maintainer-clean-libtool install-man8 \
uninstall-man8 install-man uninstall-man tags mostlyclean-tags \
distclean-tags clean-tags maintainer-clean-tags distdir info-am info \
dvi-am dvi check check-am installcheck-am installcheck install-exec-am \
install-exec install-data-am install-data install-am install \
uninstall-am uninstall all-redirect all-am all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
