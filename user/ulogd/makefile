CONFOPTS = --prefix=

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
	$(ROMFSINST) build/ulogd /bin/ulogd
	$(ROMFSINST) -d build/extensions/ulogd_BASE.so /lib/ulogd/ulogd_BASE.so
	$(ROMFSINST) build/extensions/ulogd_LOCAL.so /lib/ulogd/ulogd_LOCAL.so
	$(ROMFSINST) build/extensions/ulogd_LOGEMU.so /lib/ulogd/ulogd_LOGEMU.so
	$(ROMFSINST) build/extensions/ulogd_OPRINT.so /lib/ulogd/ulogd_OPRINT.so
	$(ROMFSINST) build/extensions/ulogd_SYSLOG.so /lib/ulogd/ulogd_SYSLOG.so
	$(ROMFSINST) build/pcap/ulogd_PCAP.so /lib/ulogd/ulogd_PCAP.so
