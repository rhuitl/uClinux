.EXPORT_ALL_VARIABLES:

CONFOPTS = NM=$(CROSS)nm OBJDUMP=$(CROSS)objdump --sysconfdir=/etc/config/ --without-afs --without-libpam

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/.libs/pam_krb5.so /lib/security/pam_krb5.so
