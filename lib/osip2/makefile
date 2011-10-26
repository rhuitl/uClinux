CONFOPTS = --disable-dependency-tracking --enable-static --disable-shared
CONFIGURE_HOST ?= $(CROSS_COMPILE:-=)

all: build/build
	$(MAKE) -C build all
	$(MAKE) -C build prefix= DESTDIR=$(shell pwd)/build/install install

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

# Nothing to install for romfs. We use static libraries only
romfs:
