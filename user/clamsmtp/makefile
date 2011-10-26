
CONFOPTS :=	--enable-dependency-tracking		\
		--sysconfdir=/etc/config

ifdef CONFIG_USER_TRUSTEDSOURCE_V2
LDLIBS += -lrep -lsnapgear -lutil
else
ifdef CONFIG_USER_TRUSTEDSOURCE_BLACKLIST
LDLIBS += -lsnapgear -lutil
endif
endif

ifdef CONFIG_USER_TRUSTEDSOURCE_BLACKLIST
LDLIBS += -lconfig $(LIBTCL) $(TS_LIBS) $(LIBCRYPT) $(LIBDL)
endif

ifdef CONFIG_PROP_TSSDK
LDLIBS += -llicense -lts $(LIBPTHREAD) $(LIBSSL) $(LIBCRYPTO)
endif

CFLAGS += -DTSPRODUCT=\"$(CONFIG_PRODUCT)\" -DVERSIONINFO=\"$(VERSIONPKG)\"

CONFOPTS += LIBS="$(LDLIBS)"

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

romfs:
	[ -d $(ROMFSDIR)/etc/clamav ] || mkdir $(ROMFSDIR)/etc/clamav
	$(ROMFSINST) build/src/clamsmtpd /bin/clamsmtpd
	$(ROMFSINST) doc/clamsmtpd.conf /etc/clamav/clamsmtpd.conf
