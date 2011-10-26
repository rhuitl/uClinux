
AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

man_MANS = ulogd.8

EXTRA_DIST = $(man_MANS) debian ulogd.logrotate ulogd.spec ulogd.conf

INCLUDES = $(all_includes) -I$(top_srcdir)/include
SUBDIRS = include doc libipulog src input filter output

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`
