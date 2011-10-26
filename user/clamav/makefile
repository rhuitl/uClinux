# Configure options.  We can't put --enable-pthreads here
# since it turns *off* pthread support which we need to make clamd
# Luckily, it autodetects pthread presence and acts appropriately.

CONFOPTS :=	--enable-dependency-tracking		\
		--disable-milter			\
		--disable-clamav			\
		--disable-unrar				\
		--with-dbdir=/var/clamav		\
		--enable-dns				\
		--with-zlib=$(STAGEDIR)			\
		--sysconfdir=/etc/config

ifdef CONFIG_PROP_CLAMAV_FILTER
CFLAGS += -DFILTER_RULES -DNO_UNRAR
LDFLAGS += -Wl,--unresolved-symbols=ignore-in-shared-libs
endif

all: build/build
	$(MAKE) -C build

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

LIB_NAME=$(notdir $(wildcard build/libclamav/.libs/libclamav.so.*.*.*))
romfs:
	[ -d $(ROMFSDIR)/etc/clamav ] || mkdir $(ROMFSDIR)/etc/clamav
ifndef CONFIG_USER_CLAMAV_NODB
	$(ROMFSINST) database/main.cvd /etc/clamav/main.cvd
	$(ROMFSINST) database/daily.cvd /etc/clamav/daily.cvd
endif
	$(ROMFSINST) build/libclamav/.libs/$(LIB_NAME) /lib/$(LIB_NAME)
	$(ROMFSINST) -s $(LIB_NAME) /lib/$(basename $(basename $(LIB_NAME)))
	$(ROMFSINST) -s $(LIB_NAME) /lib/libclamav.so
ifdef CONFIG_USER_CLAMAV_CLAMD
	$(ROMFSINST) build/clamd/.libs/clamd /bin/clamd
	$(ROMFSINST) etc/clamd.conf /etc/clamav/clamd.conf
endif
	$(ROMFSINST) -e CONFIG_USER_CLAMAV_CLAMDSCAN build/clamdscan/.libs/clamdscan /bin/clamdscan
	$(ROMFSINST) -e CONFIG_USER_CLAMAV_CLAMSCAN build/clamscan/.libs/clamscan /bin/clamscan
ifdef CONFIG_USER_CLAMAV_FRESHCLAM
	$(ROMFSINST) build/freshclam/.libs/freshclam /bin/freshclam
	$(ROMFSINST) etc/freshclam.conf /etc/clamav/freshclam.conf
endif
	$(ROMFSINST) -e CONFIG_USER_CLAMAV_SIGTOOL build/sigtool/sigtool /bin/sigtool
ifdef CONFIG_USER_CLAMAV_TESTS
	[ -d $(ROMFSDIR)/etc/clamav/test ] || mkdir $(ROMFSDIR)/etc/clamav/test
	for t in $(wildcard test/clam*); do $(ROMFSINST) $$t /etc/clamav/test/`basename $$t`; done
endif
