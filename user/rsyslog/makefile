PREFIX=
DESTDIR=$(shell pwd)/install
CONFOPTS = --prefix=$(PREFIX) --disable-klog
#--disable-shared

all: build/build
	$(MAKE) -C build
	$(MAKE) -C build install DESTDIR=$(DESTDIR)

build/build: makefile
	rm -rf build install
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build install

romfs:
	$(ROMFSINST) -f $(DESTDIR)/sbin /sbin
	$(ROMFSINST) -f $(DESTDIR)/lib /lib
