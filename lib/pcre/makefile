#
# build using configure

CONF_OPTS := --prefix=
CONF_OPTS += --host=i386-redhat-linux
CONF_OPTS += --target=$(CROSS_COMPILE:-=)
CONF_OPTS += --disable-fast-install

#CONF_OPTS += --without-threads
#CONF_OPTS += --without-local
#CONF_OPTS += --disable-ipv6
#CONF_OPTS += --enable-x-compile
#CONF_OPTS += --disable-slapd
#CONF_OPTS += --disable-slurpd

all: builddir/config.status
	$(MAKE) -C builddir MAKE="$(MAKE) -f Makefile"

romfs: builddir/config.status

builddir/config.status: makefile
	rm -rf builddir;					\
	chmod u+x configure;					\
	mkdir builddir; 					\
	cd builddir;						\
	export CFLAGS="$(subst -Wall,,$(CFLAGS))"; 		\
	export LDFLAGS='-lc';					\
	../configure $(CONF_OPTS)

clean:
	rm -rf builddir

