CONFOPTS = --prefix= \
	   --without-pgsql \
	   --without-mysql \
	   --without-sqlite3 \
	   --without-pcap

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
	$(ROMFSINST) build/src/ulogd /bin/ulogd
	$(ROMFSINST) -d build/input/flow/.libs/ulogd_inpflow_NFCT.so /lib/ulogd/ulogd_inpflow_NFCT.so
	$(ROMFSINST) -d -e CONFIG_IP_NF_TARGET_ULOG build/input/packet/.libs/ulogd_inppkt_ULOG.so /lib/ulogd/ulogd_inppkt_ULOG.so
	$(ROMFSINST) -d build/input/packet/.libs/ulogd_inppkt_NFLOG.so /lib/ulogd/ulogd_inppkt_NFLOG.so
	$(ROMFSINST) -d build/filter/.libs/ulogd_filter_IFINDEX.so /lib/ulogd/ulogd_filter_IFINDEX.so
	$(ROMFSINST) -d build/filter/.libs/ulogd_filter_PRINTPKT.so /lib/ulogd/ulogd_filter_PRINTPKT.so
	$(ROMFSINST) -d build/filter/.libs/ulogd_filter_PRINTFLOW.so /lib/ulogd/ulogd_filter_PRINTFLOW.so
	$(ROMFSINST) -d build/filter/raw2packet/.libs/ulogd_raw2packet_BASE.so /lib/ulogd/ulogd_raw2packet_BASE.so
	$(ROMFSINST) -d build/output/.libs/ulogd_output_SYSLOG.so /lib/ulogd/ulogd_output_SYSLOG.so
	$(ROMFSINST) -d build/output/.libs/ulogd_output_LOGEMU.so /lib/ulogd/ulogd_output_LOGEMU.so
