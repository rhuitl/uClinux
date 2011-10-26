
CONF_OPTS = --prefix= --disable-thread-support --sysconfdir=/etc/config

all: build
	$(MAKE) -C build

build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONF_OPTS))

romfs:
	$(ROMFSINST) build/lib/libkrb5.so.3 /lib/
	$(ROMFSINST) build/lib/libk5crypto.so.3 /lib/
	$(ROMFSINST) build/lib/libkrb5support.so.0 /lib/
	$(ROMFSINST) build/lib/libgssapi_krb5.so.2 /lib/
	$(ROMFSINST) build/lib/libcom_err.so /lib/
	$(ROMFSINST) build/lib/libcom_err.so.3 /lib/
	$(ROMFSINST) build/lib/libcom_err.so.3.0 /lib/
	$(ROMFSINST) build/clients/kinit/kinit /bin/
	$(ROMFSINST) build/clients/klist/klist /bin/
	$(ROMFSINST) build/clients/kdestroy/kdestroy /bin/	
clean:
	rm -rf build

