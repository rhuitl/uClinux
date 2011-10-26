#
# build using configure as best we can, should work for most targets
# David McCullough <davidm@snapgear.com>
#

CONFOPTS = --without-threads --without-local --disable-ipv6 \
		   --enable-x-compile --disable-slapd --disable-slurpd \
		   --prefix=

all: builddir/build
	$(MAKE) -C builddir LIBTOOL="$(LIBTOOL)"

romfs: builddir/build
	$(MAKE) -C builddir LIBTOOL="$(LIBTOOL)" romfs
	$(ROMFSINST) builddir/clients/tools/ldapsearch /bin/ldapsearch

builddir/build: makefile
	rm -rf builddir
	mkdir builddir
	(cd builddir; \
		CPP="$(CC) $(CFLAGS) -E" \
		sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	$(MAKE) -C builddir LIBTOOL="$(LIBTOOL)" depend
	touch builddir/build

clean:
	rm -rf builddir

