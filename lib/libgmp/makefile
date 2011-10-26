
CONFOPTS := --enable-static --disable-shared

all: build/build
	$(MAKE) -C build
	$(MAKE) -C build prefix= DESTDIR=$(shell pwd)/build/install install

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
