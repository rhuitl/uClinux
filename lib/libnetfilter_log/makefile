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
	$(ROMFSINST) build/src/.libs/libnetfilter_log.so.1 /lib/libnetfilter_log.so.1
	$(ROMFSINST) -e CONFIG_IP_NF_TARGET_ULOG build/src/.libs/libnetfilter_log_libipulog.so.1 /lib/libnetfilter_log_libipulog.so.1
	#$(ROMFSINST) build/utils/.libs/nfulnl_test /bin/nfulnl_test
	#$(ROMFSINST) build/utils/.libs/ulog_test /bin/ulog_test
