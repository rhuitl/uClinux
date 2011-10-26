## $Id$
AUTOMAKE_OPTIONS=foreign no-dependencies
SUBDIRS = src doc etc templates contrib schemas rpm m4

INCLUDES = @INCLUDES@

EXTRA_DIST = ChangeLog snort.8 LICENSE verstuff.pl RELEASE.NOTES

man_MANS = snort.8

DISTCLEANFILES=stamp-h.in


dist-hook:
# always ensure that the win32 build is in sync
	perl $(distdir)/verstuff.pl $(distdir)
# work around a horrible doc/Makefile.am
	rm -rf $(distdir)/doc/signatures/CVS
