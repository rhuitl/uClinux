## Process this file with automake to produce Makefile.in
#
# $Id: Makefile.am,v 1.3.2.15 2004/09/25 21:37:35 hno Exp $
#

AUTOMAKE_OPTIONS = dist-bzip2 subdir-objects 1.5
DIST_SUBDIRS	= lib snmplib scripts src icons errors contrib doc helpers
SUBDIRS		= lib @makesnmplib@ scripts src icons errors doc helpers

DISTCLEANFILES = include/stamp-h include/stamp-h[0-9]*
DEFAULT_PINGER		= $(libexecdir)/`echo pinger | sed '$(transform);s/$$/$(EXEEXT)/'`

dist-hook:
	@ for subdir in include include/samba/nsswitch; do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	    cp -p $(srcdir)/$$subdir/*.h  $(distdir)/$$subdir \
	      || exit 1; \
	    rm -f $(distdir)/$$subdir/autoconf.h; \
	  fi; \
	done
	@if [ -f $(top_srcdir)/RELEASENOTES.html ]; then \
	  cp -p $(top_srcdir)/RELEASENOTES.html $(distdir)/RELEASENOTES.html; \
	else \
	  cp $(top_srcdir)/doc/release-notes/release-2.5.html $(distdir)/RELEASENOTES.html; \
	fi

EXTRA_DIST = \
	ChangeLog \
	CONTRIBUTORS \
	COPYING \
	COPYRIGHT \
	CREDITS \
	INSTALL \
	QUICKSTART \
	README \
	SPONSORS \
	bootstrap.sh \
	include/samba/README.txt

install-pinger:
	chown root $(DEFAULT_PINGER) 
	chmod 4711 $(DEFAULT_PINGER)
