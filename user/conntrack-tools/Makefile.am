include Make_global.am

# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

man_MANS = conntrack.8
EXTRA_DIST = $(man_MANS) Make_global.am ChangeLog TODO examples

SUBDIRS   = extensions src
DIST_SUBDIRS = include src extensions
LINKOPTS  = -lnfnetlink -lnetfilter_conntrack -lpthread
AM_CFLAGS = -g

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`
	rm -rf `find $(distdir)/examples -name .svn`
