
glibc-2.3.6-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-2.3.6.tar.bz2
glibc-linuxthreads-2.3.6-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-linuxthreads-2.3.6.tar.bz2
glibc-libidn-2.3.6-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-libidn-2.3.6.tar.bz2

glibc-2.5-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-2.5.tar.bz2
glibc-linuxthreads-2.5-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-linuxthreads-2.5.tar.bz2
glibc-libidn-2.5-url := \
	http://ftp.gnu.org/gnu/glibc/glibc-libidn-2.5.tar.bz2


CONFOPTS = \
	--disable-sanity-checks \
	--with-headers=$(STAGEDIR)/include \
	--disable-profile \
	--prefix= --sysconfdir=/etc/config

# CONFOPTS += --enable-kernel=2.4.22

# do we want a non-debuggable lib or not,  if so remove the C flag and
# enable it in glibc,  it knows best where to add it.
ifneq ($(findstring -fomit-frame-pointer,$(CFLAGS)),)
	CONFOPTS += --enable-omitfp
	CFLAGS := $(subst -fomit-frame-pointer,,$(CFLAGS))
endif

CFLAGS := $(subst -fno-common,,$(CFLAGS))
CFLAGS := $(subst -fno-builtin,,$(CFLAGS)) -fgnu89-inline
repl = -Wl,--fatal-warnings
LDFLAGS := $(subst $(repl),,$(LDFLAGS))
LDFLAGS := $(subst -nostdlib,,$(LDFLAGS))
LDFLAGS := $(subst -nostartfiles,,$(LDFLAGS))
export CFLAGS LDFLAGS

BUILD_CC = $(HOSTCC)
export BUILD_CC

ifdef CONFIG_GLIBC_2_3_6
GLIBC_ALL = glibc-2.3.6-all
endif
ifdef CONFIG_GLIBC_2_5
GLIBC_ALL = glibc-2.5-all
endif

WGET ?= wget

all: $(GLIBC_ALL)

%.tar.bz2 %.tar.gz:
	@echo "Downloading $* ..."
	@[ -d "$$HOME/.downloads" ] || mkdir ~/.downloads
	@if [ ! -f "$$HOME/.downloads/$@" ]; then \
		(cd ~/.downloads; $(WGET) "$($*-url)"); \
	fi
	@if [ -f "$$HOME/.downloads/$@" ]; then \
			ln -fs "$$HOME/.downloads/$@" $@; \
	fi
	if [ ! -f "$@" ]; then \
		echo "Cannot find download for $@" >&2 ; \
		exit 1; \
	fi

glibc-2.5-all: glibc-2.5-configured
	rm -rf install
	mkdir install
	env LANGUAGE=C LC_ALL=C $(MAKE) -C glibc-2.5 -f Makefile -r srcdir=`pwd` objdir=`pwd`/build install_root=`pwd`/install install
	: fix groups in linker scripts
	@find install/. -type f -name *.so* | while read t; do \
		if file "$$t" | grep -i ascii > /dev/null; then \
			echo "Fixing $$t ..."; \
			sed 's?\([ 	(]\)\(/lib/[^ 	)]*\)?\1'"`pwd`/install"'\2?g' < "$$t" > "$$t.fixup"; \
			cp "$$t.fixup" "$$t"; \
			rm -f "$$t.fixup"; \
		fi \
	done

glibc-2.5-extracted: Makefile glibc-2.5.tar.bz2 glibc-linuxthreads-2.5.tar.bz2 glibc-libidn-2.5.tar.bz2
	rm -rf glibc-2.5 glibc-libidn-2.5 install build
	bunzip2 < glibc-2.5.tar.bz2 | tar xf -
	bunzip2 < glibc-linuxthreads-2.5.tar.bz2 | (cd glibc-2.5; tar xf -)
	bunzip2 < glibc-libidn-2.5.tar.bz2 | tar xf -
	mv glibc-libidn-2.5 glibc-2.5/libidn
	rm -rf glibc-2.5/nptl glibc-2.5/nptl_db
	@for i in glibc-2.5*.patch; do \
		[ -f $$i ] || continue; \
		echo "Applying $$i ..."; \
		(cd glibc-2.5; patch -p1) < $$i; \
	done
	touch $@

glibc-2.5-configured: Makefile glibc-2.5-extracted
	rm -rf build
	mkdir build
	(cd build; \
		CC="$(subst ucfront-gcc,,$(CC))" \
		CXX="$(subst ucfront-g++,,$(CXX))" \
		libc_cv_ssp=no \
		/bin/bash ../glibc-2.5/configure $(CONFIGURE_OPTS) $(CONFOPTS) \
			--enable-addons=libidn,linuxthreads; \
	)
	mkdir build/dlfcn
	ln -s libdl.so build/dlfcn/libdl.so.2
	touch $@

glibc-2.3.6-all: glibc-2.3.6-configured
	rm -rf install
	mkdir install
	env no_deps=t LANGUAGE=C LC_ALL=C make -C build -f Makefile install_root=`pwd`/install
	env no_deps=t LANGUAGE=C LC_ALL=C make -C build -f Makefile install_root=`pwd`/install install
	: fix groups in linker scripts
	@find install/. -type f -name *.so* | while read t; do \
		if file "$$t" | grep -i ascii > /dev/null; then \
			echo "Fixing $$t ..."; \
			sed 's?\([ 	(]\)\(/lib/[^ 	)]*\)?\1'"`pwd`/install"'\2?g' < "$$t" > "$$t.fixup"; \
			cp "$$t.fixup" "$$t"; \
			rm -f "$$t.fixup"; \
		fi \
	done

glibc-2.3.6-extracted: Makefile glibc-2.3.6.tar.bz2 glibc-linuxthreads-2.3.6.tar.bz2 glibc-libidn-2.3.6.tar.bz2
	rm -rf glibc-2.3.6 install build
	bunzip2 < glibc-2.3.6.tar.bz2 | tar xf -
	bunzip2 < glibc-linuxthreads-2.3.6.tar.bz2 | (cd glibc-2.3.6; tar xf -)
	bunzip2 < glibc-libidn-2.3.6.tar.bz2 | (cd glibc-2.3.6; tar xf -)
	rm -rf glibc-2.3.6/nptl
	rm -rf glibc-2.3.6/nptl_db
	@for i in glibc-2.3.6*.patch; do \
		[ -f $$i ] || continue; \
		echo "Applying $$i ..."; \
		(cd glibc-2.3.6; patch -p1) < $$i; \
	done
	touch $@

glibc-2.3.6-configured: Makefile glibc-2.3.6-extracted
	rm -rf build
	mkdir build
	(cd build; \
		CC="$(subst ucfront-gcc,,$(CC))" \
		CXX="$(subst ucfront-g++,,$(CXX))" \
		/bin/bash ../glibc-2.3.6/configure $(CONFIGURE_OPTS) $(CONFOPTS) \
			--with-tls --without-__thread \
			--enable-add-ons=libidn,linuxthreads; \
	)
	#mkdir build/dlfcn
	#ln -s libdl.so build/dlfcn/libdl.so.2
	touch $@

clean:
	rm -rf build install
	rm -rf glibc-2.5 glibc-2.5-extracted
	rm -rf glibc-2.3.6 glibc-2.3.6-extracted
	rm -f glibc-*.tar.bz2 glibc-*.tar.gz

romfs:
	@for i in install; do \
		echo "Installing `basename $$i -install` ..."; \
		$(ROMFSINST) -f $$i/bin /bin; \
		$(ROMFSINST) -f $$i/lib /lib; \
		$(ROMFSINST) -f $$i/etc /etc; \
		mv $(ROMFSDIR)/etc/config/* $(ROMFSDIR)/etc/default > /dev/null 2>&1; \
		$(ROMFSINST) -f $$i/share /share; \
	done
	rm -f $(ROMFSDIR)/lib/*.a
	rm -f $(ROMFSDIR)/lib/*.la
