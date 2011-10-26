CONFOPTS=

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure --prefix= --sbindir=/bin $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_PPTPD_PPTPD build/pptpd /bin/pptpd
	$(ROMFSINST) -e CONFIG_USER_PPTPD_PPTPCTRL build/pptpctrl /bin/pptpctrl

