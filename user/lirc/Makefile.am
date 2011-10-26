## $Id: Makefile.am,v 5.7 2001/01/27 18:58:36 columbus Exp $

## Process this file with automake to produce Makefile.in 
## Makefile.am, (c)1999 Tom Wheeley <tw104@york.ac.uk>

## we need version 1.4 of automake for DIST_SUBDIRS to work.
AUTOMAKE_OPTIONS = 1.4 check-news

EXTRA_DIST = setup.sh ANNOUNCE TODO

SUBDIRS = drivers daemons tools doc

## From automake documentation:
## Note that EXTRA_DIST can only handle files in the current
## directory; files in other directories will cause make dist runtime
## failures.

dist-hook:
	for f in contrib remotes; do \
		cp -pr $(srcdir)/$$f $(distdir)/$$f; done
	rm -r `find $(distdir) -name "CVS"`
	-rcs2log >$(distdir)/ChangeLog

dist-bz2: dist
	gunzip -c @PACKAGE@-@VERSION@.tar.gz | bzip2 >@PACKAGE@-@VERSION@.tar.bz2

DISTCLEANFILES = configure.sh .setup.config

CLEANFILES = *~ remotes/*~ contrib/*~
