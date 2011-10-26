PREFIX=
DESTDIR=$(shell pwd)/install
CONFOPTS = --prefix=$(PREFIX) --with-classpath-install-dir=$(PREFIX) --disable-shared --enable-ffi
CFLAGS += -DDEFAULT_MAX_HEAP=16*MB

all: build/build
	$(MAKE) -C build
	$(MAKE) -C build/src install-exec DESTDIR=$(DESTDIR)
	$(MAKE) -C build/lib install-data DESTDIR=$(DESTDIR)

build/build: makefile
	rm -rf build install
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build install

romfs:
	$(ROMFSINST) -f $(DESTDIR)/bin /bin
	$(ROMFSINST) -f $(DESTDIR)/share /share
