
CONFOPTS := --enable-dependency-tracking
CONFOPTS += --sysconfdir=/etc/config
CONFOPTS += --disable-nls --disable-largefile

CC += -DHOST_NAME_MAX=255

CFLAGS += -DOMIT_NIS

ifdef CONFIG_PROP_STATSD_STATSD
CFLAGS += -DPAM_STATS
endif
CFLAGS += -DPAM_STATS

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

INST_MODULES := pam_deny.so pam_permit.so pam_limits.so pam_nologin.so pam_rootok.so pam_warn.so pam_tally.so pam_echo.so
romfs:
	$(ROMFSINST) build/libpamc/.libs/libpamc.so.0.81.0 /lib/libpamc.so.0.81.0
	$(ROMFSINST) -s libpamc.so.0.81.0 /lib/libpamc.so.0
	$(ROMFSINST) -s libpamc.so.0.81.0 /lib/libpamc.so
	$(ROMFSINST) build/libpam/.libs/libpam.so.0.81.2 /lib/libpam.so.0.81.2
	$(ROMFSINST) -s libpam.so.0.81.2 /lib/libpam.so.0
	$(ROMFSINST) -s libpam.so.0.81.2 /lib/libpam.so
	$(ROMFSINST) build/libpam_misc/.libs/libpam_misc.so.0.81.2 /lib/libpam_misc.so.0.81.2
	$(ROMFSINST) -s libpam_misc.so.0.81.2 /lib/libpam_misc.so.0
	$(ROMFSINST) -s libpam_misc.so.0.81.2 /lib/libpam_misc.so
	for i in $(INST_MODULES); do [ "`find build/modules -name $$i`" ] && $(ROMFSINST) -d `find build/modules -name $$i` /lib/security/$$i; done
	$(ROMFSINST) build/modules/pam_tally/.libs/pam_tally /bin/pam_tally
