CONFOPTS = --with-pcap=linux
ifdef CONFIG_IPV6
CONFOPTS += --enable-ipv6
endif
ifndef CONFIG_LIB_LIBNL_GENERIC
CONFOPTS += --without-libnl
endif

all: build/
	$(MAKE) -f Makefile

build: makefile
	rm -f build
	(ac_cv_linux_vers=2 sh configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build

clean:
	if test -s Makefile; then $(MAKE) -f Makefile clean; fi
	rm -f build
	rm -f Makefile
romfs:
