-include ../user.mak

INSTALL_USER := $(shell id -un)
OPENSSLLIBS  := $(ROOTDIR)/lib/libssl/build
export DESTDIR	 := $(shell pwd)/build

# Define the directories we are going to build.
# There are four base targets present here:
#	nessus-libraries libnasl nessus-core nessus-plugins

ALL_DIRS   := nessus-libraries libnasl nessus-core nessus-plugins
BUILD_DIRS := 
ifdef CONFIG_USER_NESSUS_NASL
BUILD_DIRS += libnasl
endif
ifdef CONFIG_USER_NESSUS_CORE
BUILD_DIRS += nessus-core
endif
ifdef CONFIG_USER_NESSUS_PLUGINS
BUILD_DIRS += nessus-plugins
endif
ifdef CONFIG_USER_NESSUS_LIBRARIES
BUILD_DIRS += nessus-libraries
endif

.PHONY: all romfs clean
.PHONY: nessus-libraries libnasl nessus-core nessus-plugins

all: $(BUILD_DIRS)

clean:
	rm -rf build
	-for i in $(ALL_DIRS) ; do $(MAKE) -C $$i clean ; done
	rm -f libnasl/config.cache
	rm -f libnasl/config.log
	rm -f libnasl/config.status
	rm -f libnasl/libtool
	rm -f libnasl/nasl-config
	rm -f libnasl/nasl.tmpl
	rm -f libnasl/include/config.h
	rm -f libnasl/nasl/strutils.h
	rm -f libnasl/confdefs.h
	rm -f nessus-core/confdefs.h
	rm -f nessus-core/config.cache
	rm -f nessus-core/config.log
	rm -f nessus-libraries/config.cache
	rm -f nessus-libraries/config.log
	rm -f nessus-libraries/config.status
	rm -f nessus-libraries/libtool
	rm -f nessus-libraries/nessus-config
	rm -f nessus-libraries/nessus-config.pre
	rm -f nessus-libraries/nessus.tmpl
	rm -f nessus-libraries/uninstall-nessus
	rm -f nessus-libraries/include/config.h
	rm -f nessus-libraries/include/libvers.h
	rm -f nessus-libraries/libpcap-nessus/Makefile
	rm -f nessus-libraries/libpcap-nessus/config.log
	rm -f nessus-libraries/libpcap-nessus/config.status
	rm -f nessus-libraries/confdefs.h
	rm -rf nessus-libraries/libnessus/.libs
	rm -rf nessus-libraries/libpcap-nessus/.libs

distclean:
	rm -rf build
	-for i in $(ALL_DIRS) ; do $(MAKE) -C $$i distclean ; done

romfs:
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	$(DESTDIR)/lib/libhosts_gatherer.so.2.2.9	\
													/lib/libhosts_gatherer.so.2.2.9
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libhosts_gatherer.so.2.2.9				\
													/lib/libhosts_gatherer.so
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libhosts_gatherer.so.2.2.9				\
													/lib/libhosts_gatherer.so.2
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	$(DESTDIR)/lib/libnessus.so.2.2.9			\
													/lib/libnessus.so.2.2.9
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libnessus.so.2.2.9		/lib/libnessus.so
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libnessus.so.2.2.9		/lib/libnessus.so.2
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	$(DESTDIR)/lib/libpcap-nessus.so.2.2.9		\
													/lib/libpcap-nessus.so.2.2.9
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libpcap-nessus.so.2.2.9					\
													/lib/libpcap-nessus.so
	$(ROMFSINST) -e CONFIG_USER_NESSUS_LIBRARIES	-s libpcap-nessus.so.2.2.9					\
													/lib/libpcap-nessus.so.2
	$(ROMFSINST) -e CONFIG_USER_NESSUS_NASL			$(DESTDIR)/lib/libnasl.so.2.2.9				\
													/lib/libnasl.so.2.2.9
	$(ROMFSINST) -e CONFIG_USER_NESSUS_NASL			-s libnasl.so.2.2.9			/lib/libnasl.so
	$(ROMFSINST) -e CONFIG_USER_NESSUS_NASL			-s libnasl.so.2.2.9			/lib/libnasl.so.2
	$(ROMFSINST) -e CONFIG_USER_NESSUS_NASL			$(DESTDIR)/bin/nasl 		/bin/nasl
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/sbin/nessusd 	/sbin/nessusd
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/sbin/nessus-adduser 				\
													/sbin/nessus-adduser
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/sbin/nessus-update-plugins 		\
													/sbin/nessus-update-plugins
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/sbin/nessus-mkcert				\
													/sbin/nessus-mkcert
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/bin/nessus 		/bin/nessus
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE			$(DESTDIR)/bin/nessus-mkcert-client 		\
													/bin/nessus-mkcert-client
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE	-d		$(DESTDIR)/var 				/home/nessus/var
	$(ROMFSINST) -e CONFIG_USER_NESSUS_CORE	-d		config/users 								\
													/home/nessus/var/nessus/users
	$(ROMFSINST) -e CONFIG_USER_NESSUS_PLUGINS		$(DESTDIR)/lib/nessus 		/lib/nessus
	$(ROMFSINST) -e CONFIG_USER_NESSUS_PLUGINS		-s /var/.desc  								\
													/lib/nessus/plugins/.desc

build:
	mkdir -p build

# The base libraries are needed for everything
nessus-libraries/config.status: build Makefile
	$(MAKE) -C nessus-libraries distclean ;				\
	cd nessus-libraries ; 								\
		LDFLAGS="$(LDFLAGS)"							\
		sh configure $(CONFIGURE_OPTS) 					\
			--with-ssl=$(OPENSSLLIBS)					\
			--disable-fast-install 						\
			--cache-file config.cache					\
			--sysconfdir=/etc/config					\
			--sharedstatedir=/var						\
			--localstatedir=/var						\
			--datadir=/var								\
			--without-x                                 \
			--prefix=

nessus-libraries: build nessus-libraries/config.status
	$(MAKE) -C nessus-libraries
	$(MAKE) -C nessus-libraries install

# Includes the NASL scripting language
libnasl/config.status: nessus-libraries Makefile
	cd libnasl ; 										\
		sh configure $(CONFIGURE_OPTS)  				\
			--disable-fast-install						\
			--cache-file config.cache					\
			--sysconfdir=/etc/config					\
			--sharedstatedir=/var						\
			--localstatedir=/var						\
			--datadir=/var								\
			--without-x                                 \
			--prefix=

libnasl: nessus-libraries libnasl/config.status
	$(MAKE) -C libnasl
	$(MAKE) -C libnasl install

# Includes the nessus daemon and nessus command line tool
nessus-core/config.status: libnasl Makefile
	cd nessus-core ; 									\
		sh configure $(CONFIGURE_OPTS)  				\
			--disable-fast-install 						\
			--cache-file config.cache --disable-gtk 	\
			--sysconfdir=/etc/config					\
			--sharedstatedir=/var						\
			--localstatedir=/var						\
			--datadir=/var								\
			--without-x                                 \
			--prefix=

nessus-core: libnasl nessus-core/config.status
	$(MAKE) -C nessus-core 
	$(MAKE) -C nessus-core install

# The scripts etc
nessus-plugins/config.status: nessus-core Makefile
	cd nessus-plugins ; 								\
		sh configure $(CONFIGURE_OPTS)  				\
			--disable-fast-install 						\
			--cache-file config.cache 					\
			--enable-install=$(INSTALL_USER)			\
			--sysconfdir=/etc/config					\
			--sharedstatedir=/var						\
			--localstatedir=/var						\
			--datadir=/var								\
			--without-x                                 \
			--prefix=

nessus-plugins: nessus-core nessus-plugins/config.status
	$(MAKE) -C nessus-plugins
	$(MAKE) -C nessus-plugins install
# DO NOT DELETE
