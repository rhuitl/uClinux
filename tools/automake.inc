# Makefile to auto build tarball's with patches etc
# see Documentation/automake.txt for more info on using this file
# Copyright (C) 2009 David McCullough <davidm@uclinux.org>

.EXPORT_ALL_VARIABLES:

#
# these config options apply to all things we build
#
CONFOPTS += \
    --prefix= \
    --sysconfdir=/etc/config

CONFOPTS += --with-vendor-name=$(CONFIG_VENDOR)
CONFOPTS += --with-vendor-name-short=$(CONFIG_VENDOR)
CONFOPTS += --with-os-name=uClinux-dist
CONFOPTS += --with-os-vendor=uClinux
CONFOPTS += --disable-static

#
# for uClibc without glibc compat
#
CONFOPTS += --enable-malloc0returnsnull

#
# make sure LD does the right thing during configure if invoked directly
#
LDFLAGS  += -Wl,-L$(STAGEDIR)/lib -Wl,-rpath-link -Wl,$(STAGEDIR)/lib

#
# where our pkgconfig stuff will go
#
PKG_CONFIG_LIBDIR=$(STAGEDIR)/lib/pkgconfig

#
# its generally a bad idea to fail on linker warnings for packages we
# aren't fully controlling,  though we could put this back conditionally
#
LDFLAGS := $(LDFLAGS:-Wl,--fatal-warnings=)

BUILD_CC = $(HOSTCC)
HOST_CC      = gcc
HOST_CXX     = g++
HOST_RANLIB  = $(shell which ranlib || echo :)

#
# we use wget to download
#
WGET ?= wget

#
# force using our special libtool
#
MAKEVARS     ?= LIBTOOL="$(LIBTOOL)"

#
# remap directories in a build to ensure that only uClinux-dist files
# are used
#
UCFRONT_MAPDIRS  = /lib/=$(STAGEDIR)/lib/
UCFRONT_MAPDIRS += /usr/lib=$(STAGEDIR)/usr/lib
UCFRONT_MAPDIRS += /include/=$(STAGEDIR)/include/
UCFRONT_MAPDIRS += /usr/include=$(STAGEDIR)/usr/include

#
# some short cut config,  just set URL = blah
# and we work the rest out
#
ifdef URL
  PKG := $(shell basename $(URL))
  PKG := $(PKG:.tar.gz=)
  PKG := $(PKG:.tar.bz2=)
  PKG := $(PKG:.tgz=)
  PKG := $(PKG:.tbz2=)
  PKG := $(PKG:.zip=)
  AUTOMAKE_y += $(PKG)
endif

define pkg_def
  $(1)_URL ?= $(URL)
  $(1)_INSTALL ?= $(if $(INSTALL),$(INSTALL),install)
  $(1)_NODEFCONF ?= $(NODEFCONF)
  $(1)_AUTOCONF ?= $(AUTOCONF)
  $(1)_CONFIGURE ?= $(if $(CONFIGURE),$(CONFIGURE),configure)
  $(1)_BUILDDIR ?= $(if $(BUILDDIR),$(BUILDDIR),$(1))
  $(1)_SRCDIR ?= $(if $(SRCDIR),$(SRCDIR),$(1))
endef
$(foreach pkg,$(AUTOMAKE_y),$(eval $(call pkg_def,$(pkg))))

#
# allow some targets to be overridden
#
BUILDTARGET ?= built
INSTALLTARGET ?= installed

#
# the main target
#
all: $(foreach pkg,$(AUTOMAKE_y),build/$(pkg)-lndir)

.PHONY: force_target
force_target:

.PRECIOUS: $(addprefix build/,$(addsuffix -extracted,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -configured,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -built,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -installed,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -patched,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -$(BUILDTARGET),$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -$(INSTALLTARGET),$(AUTOMAKE_y)))

downloads/%.tar.bz2 downloads/%.tar.gz downloads/%.zip:
	echo "Downloading $* ..."
	[ -d "$$HOME/.downloads" ] || mkdir ~/.downloads
	set -x;if [ ! -f "$$HOME/.downloads/`basename $@`" ]; then \
		(cd ~/.downloads; $(WGET) "$($*_URL)"); \
	fi
	mkdir -p `dirname $@`
	if [ -f "$$HOME/.downloads/`basename $@`" ]; then \
			ln -fs "$$HOME/.downloads/`basename $@`" $@; \
	fi
	if [ ! -f "$@" ]; then \
		echo "Cannot find download for $@" >&2 ; \
		exit 1; \
	fi

define download_dep
.PRECIOUS: downloads/$(shell basename "$($(1)_URL)")
build/$(1)-extracted: downloads/$(shell basename "$($(1)_URL)")
	mkdir -p build
	case "$$^" in \
	*zip) mkdir -p build/$(1); pkg=`pwd`/$$^; (cd build/$(1); unzip $$$$pkg);; \
	*bz2) bunzip2 < $$^ | (cd build; tar xf -);; \
	*) gunzip < $$^ | (cd build; tar xf -);; \
	esac
	touch $$@
endef

$(foreach pkg,$(AUTOMAKE_y),$(eval $(call download_dep,$(pkg))))

build/%-patched: build/%-extracted
	@if [ -f patches/series ]; then \
		while read t; do \
			echo "patching with patches/$$t"; \
			[ ! -f patches/$$t ] || (cd build/$($*_SRCDIR); patch -E -p1) < patches/$$t; \
		done < patches/series; \
	else \
		for i in patches/$**.patch; do \
			echo "patching with $$i"; \
			[ ! -f $$i ] || (cd build/$($*_SRCDIR); patch -E -p1) < $$i; \
		done; \
	fi
	touch $@

build/%-autoconf: build/%-patched
	$(if $($*_AUTOCONF),cd build/$($*_SRCDIR); $($*_AUTOCONF))
	touch $@

build/%-configured: build/%-autoconf
	mkdir -p build/$($*_BUILDDIR)
	cd build/$($*_BUILDDIR); \
		if [ -f $($*_CONFIGURE) ]; then \
			$(CONFVARS) \
			$($*_CONFVARS) \
			CFLAGS="$(CFLAGS) $($*_CFLAGS)" \
			sh $($*_CONFIGURE) $(if $($*_NODEFCONF),,$(CONFIGURE_OPTS) $(CONFOPTS)) $($*_CONFOPTS); \
		fi
	touch $@

build/%-built: build/%-configured
	$(BUILDVARS) \
	$($*_BUILDVARS) \
		$(MAKE) -C build/$($*_BUILDDIR) $(MAKEVARS) $($*_MAKEVARS)
	touch $@

build/%-installed: build/%-$(BUILDTARGET)
	mkdir -p build/$*-install
	$(BUILDVARS) \
	$($*_BUILDVARS) \
		$(MAKE) -C build/$($*_BUILDDIR) $($*_INSTALL) DESTDIR=`pwd`/build/$*-install $(MAKEVARS) $($*_MAKEVARS)
	touch $@

build/%-lndir: build/%-$(INSTALLTARGET) force_target
	mkdir -p build/$*-install
	@cd build/$*-install; find . \( -type f -o -type l \) | egrep -v '.la$$' | \
	while read t; do \
		case "$$t" in \
		./bin/*) continue;; \
		./sbin/*) continue;; \
		esac; \
		rm -f $(STAGEDIR)/$$t; \
		mkdir -p "`dirname \"$(STAGEDIR)/$$t\"`"; \
		ln -s "`pwd`/$$t" "$(STAGEDIR)/$$t"; \
		echo "ln -s \"`pwd`/$$t\" \"$(STAGEDIR)/$$t\""; \
	done
	touch $@

clean:
	rm -rf build downloads

romfs_pre:
	@for i in build/*-install; do \
		echo "Installing `basename $$i -install` ..."; \
		[ ! -d $$i/usr ] || $(ROMFSINST) -v -f $$i/usr /usr; \
		[ ! -d $$i/bin ] || $(ROMFSINST) -v -f $$i/bin /bin; \
		[ ! -d $$i/sbin ] || $(ROMFSINST) -v -f $$i/sbin /sbin; \
		[ ! -d $$i/lib ] || $(ROMFSINST) -v -f $$i/lib /lib; \
		rm -rf $$i/etc/default; \
		[ ! -d $$i/etc/config ] || mv $$i/etc/config $$i/etc/default; \
		[ ! -d $$i/etc ] || $(ROMFSINST) -v -f $$i/etc /etc; \
		[ ! -d $$i/share ] || $(ROMFSINST) -v -f $$i/share /share; \
	done
	rm -f $(ROMFSDIR)/lib/*.a
	rm -f $(ROMFSDIR)/lib/*.la

romfs_post: $(foreach pkg,$(AUTOMAKE_y),$($(pkg)_ROMFS))

romfs: $(if $(AUTOMAKE_ROMFS),$(AUTOMAKE_ROMFS),romfs_pre) romfs_post

