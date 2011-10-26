insmod_SOURCES = insmod.c testing.h
lsmod_SOURCES = lsmod.c testing.h
modprobe_SOURCES = modprobe.c zlibsupport.c testing.h zlibsupport.h
rmmod_SOURCES = rmmod.c testing.h
depmod_SOURCES = depmod.c moduleops.c tables.c zlibsupport.c depmod.h moduleops.h tables.h list.h testing.h  zlibsupport.h
modinfo_SOURCES = modinfo.c zlibsupport.c testing.h zlibsupport.h

insmod_static_SOURCES = insmod.c
insmod_static_LDFLAGS = -static
# We don't want the $(zlib_flags) here: that makes a dynamic executable
insmod_static_LDADD = 

EXTRA_insmod_SOURCES = backwards_compat.c
EXTRA_lsmod_SOURCES = backwards_compat.c
EXTRA_modprobe_SOURCES = backwards_compat.c
EXTRA_rmmod_SOURCES = backwards_compat.c
EXTRA_insmod_static_SOURCES = backwards_compat.c
EXTRA_depmod_SOURCES = moduleops_core.c
EXTRA_modinfo_SOURCES = backwards_compat.c

MAN5 = modprobe.conf.5 modules.dep.5
MAN8 = depmod.8 insmod.8 lsmod.8 rmmod.8 modprobe.8 modinfo.8
SGML = $(addprefix doc/,  $(MAN5:%.5=%.sgml) $(MAN8:%.8=%.sgml))
man_MANS = $(MAN5) $(MAN8)
# If they haven't overridden mandir, fix it (never /man!)
mandir =$(shell if [ @mandir@ = $(prefix)/man ]; then if [ $(prefix) = / ]; then echo /usr/share/man; else echo $(prefix)/share/man; fi; else echo @mandir@; fi)

TESTSUITE := $(shell find tests -type f ! -name '*~') tests/vg-suppressions

EXTRA_DIST = generate-modprobe.conf modprobe.devfs FAQ CODING stress_modules.sh install-with-care $(SGML) $(man_MANS) $(TESTSUITE)

sbin_PROGRAMS = insmod modprobe rmmod depmod modinfo insmod.static
bin_PROGRAMS = lsmod
sbin_SCRIPTS = generate-modprobe.conf
INSTALL = $(SHELL) $(top_srcdir)/install-with-care

TESTS = tests/runtests

DIST_DIR := /home/rusty/devel/kernel/www/modules/

MAINTAINERCLEANFILES := $(man_MANS)

# According to Warren Togami, RH has docbook2man in the docbook-utils rpm.
DOCBOOKTOMAN := $(shell if command -v docbook-to-man >/dev/null 2>&1; then echo docbook-to-man; else echo docbook2man; fi)

# docbook2man writes file itself, doesn't do stdout.
%.8: doc/%.sgml
	if [ "$(DOCBOOKTOMAN)" = "docbook2man" ]; then                     \
	    $(DOCBOOKTOMAN) $< > /dev/null 2>&1;                       \
	else                                                               \
	    $(DOCBOOKTOMAN) $< 2>&1 > $@ | sed 's/^[^:]*://';              \
	fi

%.5: doc/%.sgml
	if [ "$(DOCBOOKTOMAN)" = "docbook2man" ]; then                     \
	    $(DOCBOOKTOMAN) $< > /dev/null 2>&1;                       \
	else                                                               \
	    $(DOCBOOKTOMAN) $< 2>&1 > $@ | sed 's/^[^:]*://';              \
	fi

# docbook2man creates extra crap files which need cleaning.
distclean: killbuildmanpages

killbuildmanpages:
	rm -f doc/*.tmp manpage.refs manpage.links

tarball: $(DIST_DIR)/module-init-tools-$(VERSION).tar.gz

$(DIST_DIR)/module-init-tools-$(VERSION).tar.gz: dist
	mv module-init-tools-$(VERSION).tar.gz $@

srpm: $(DIST_DIR)/module-init-tools-$(VERSION).tar.gz
	ln -sf $(DIST_DIR)/module-init-tools-$(VERSION).tar.gz /usr/src/rpm/SOURCES/
	set -e; RELEASE=`grep '^Release:' /usr/src/rpm/SPECS/modutils.spec | awk '{ print $$2 }'`; \
	if [ "`grep '%define mit_ver' /usr/src/rpm/SPECS/modutils.spec | awk '{print $$3}'`" != $(VERSION) ]; then \
		sed -e "s/Release: $$RELEASE/Release: `expr $$RELEASE + 1`/" -e 's/%define mit_ver.*/%define mit_ver $(VERSION)/' < /usr/src/rpm/SPECS/modutils.spec > /tmp/modutils.spec; \
		rpm -ba /tmp/modutils.spec; \
		mv /usr/src/rpm/SRPMS/modutils-2.4.21-`expr $$RELEASE + 1`.src.rpm $(DIST_DIR); \
		mv /tmp/modutils.spec /usr/src/rpm/SPECS/modutils.spec; \
	else \
		rpm -ba /usr/src/rpm/SPECS/modutils.spec; \
		mv /usr/src/rpm/SRPMS/modutils-2.4.21-$$RELEASE.src.rpm $(DIST_DIR); \
	fi

# No testsuite?
tests/runtests:
	mkdir tests
	echo '#! /bin/sh' > $@
	echo '# Install the testsuite over this dir. ' >> $@
	chmod a+x $@

$(DIST_DIR)/module-init-tools-testsuite-$(VERSION).tar.gz:
	ln -sfn `pwd` /tmp/module-init-tools-$(VERSION) 
	cd /tmp && tar --exclude '*~' -c -z -f $@ module-init-tools-$(VERSION)/tests
	rm /tmp/module-init-tools-$(VERSION)

release: check clean tarball

moveold: check-for-sbin check-for-old move-old-targets

check-for-sbin:
	if [ "`echo $(DESTDIR)$(sbindir) | tr -s / /`" = /sbin ]; then :;    \
	else								     \
		echo moveold usually only makes sense when installing into /sbin; \
		exit 1;							     \
	fi

check-for-old:
	if [ -f /sbin/lsmod.old ]; then					\
		echo Someone already moved old versions. >&2; exit 1;	\
	fi

# Don't just move symlinks, reset them to point to xxx.old.
# RedHat 8.0 doesn't ship with readlink by default.  Use ls -l.
# Also, make symlink from /bin to /sbin for lsmod (FHS compliant).
move-old-targets:
	for f in lsmod modprobe rmmod depmod insmod modinfo; do		    \
	    if [ -L /sbin/$$f ]; then					    \
		ln -sf `ls -l /sbin/$$f | sed 's/.* -> //'`.old /sbin/$$f;  \
	    fi;								    \
	    mv /sbin/$$f /sbin/$$f.old;					    \
	    if [ -f /usr/share/man/man8/$$f.8.gz ]; then		    \
		mv /usr/share/man/man8/$$f.8.gz				    \
			/usr/share/man/man8/$$f.old.8.gz;		    \
	    elif [ -f /usr/share/man/man8/$$f.8.bz2 ]; then		    \
	        mv /usr/share/man/man8/$$f.8.bz2			    \
			/usr/share/man/man8/$$f.old.8.bz2;		    \
	    else							    \
	        mv /usr/share/man/man8/$$f.8 /usr/share/man/man8/$$f.old.8; \
	    fi;								    \
	done
	for f in kallsyms ksyms; do					    \
	    if [ -L /sbin/$$f ]; then					    \
		ln -sf `ls -l /sbin/$$f | sed 's/.* -> //'`.old /sbin/$$f;  \
	    fi;								    \
	done
	ln -s /sbin/lsmod.old /bin/lsmod.old

# For installs in /usr/local/sbin
links:
	for f in insmod modprobe rmmod depmod; do ln -s /sbin/$$f $(DESTDIR)$(sbindir)/$$f.old; done
	for f in  lsmod; do ln -s /sbin/$$f $(DESTDIR)$(bindir)/$$f.old; done
