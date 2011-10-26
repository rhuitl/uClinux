SUBDIRS = lib src doc
DIST_SUBDIRS = lib src doc
EXTRA_DIST = bootstrap include/config.h.in BUGS cacheconv.pl

dist-hook:
	-chmod -R a+r $(distdir)
	$(TAR) -cho $(distdir) | $(BZIP2) >$(distdir).tar.bz2
