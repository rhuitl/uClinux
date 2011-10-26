CONFOPTS = --with-crypto --disable-smb
ifdef CONFIG_IPV6
CONFOPTS += --enable-ipv6
endif
ifdef CONFIG_LIB_LIBNL_GENERIC
LDFLAGS += -lnl
endif

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
	$(ROMFSINST) build/tcpdump /bin/tcpdump
