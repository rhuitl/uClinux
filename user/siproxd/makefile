-include ../user.mak

#CONFOPTS=--with-libosip-prefix=$(ROOTDIR)/user/libosip2/build/usr/local

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
	$(ROMFSINST) build/src/siproxd /bin/siproxd
