CONFOPTS = --prefix=
DESTDIR=$(shell pwd)/install

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
	$(ROMFSINST) $(DESTDIR)/lib/libffi.so.5 /lib/libffi.so.5
