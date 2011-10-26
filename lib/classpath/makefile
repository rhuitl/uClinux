CONFOPTS = --prefix= --disable-gtk-peer --disable-gconf-peer --disable-plugin
DESTDIR=$(shell pwd)/install

all: build/build
	$(MAKE) -C build
	$(MAKE) -C build/lib install-data DESTDIR=$(DESTDIR)
	$(MAKE) -C build/native install-exec DESTDIR=$(DESTDIR)
	#$(MAKE) -C build/tools install-exec DESTDIR=$(DESTDIR)
	#$(MAKE) -C build/tools install-data DESTDIR=$(DESTDIR)

build/build:
	rm -rf build install
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	mkdir -p build/lib/META-INF
	touch build/build

clean:
	rm -rf build install

romfs:
	$(ROMFSINST) -f $(DESTDIR)/lib /lib
	$(ROMFSINST) -f $(DESTDIR)/share /share
	#$(ROMFSINST) $(DESTDIR)/bin/*-gkeytool /bin/gkeytool
