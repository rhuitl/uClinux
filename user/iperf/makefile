-include ../user.mak

CONFOPTS=--disable-threads

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; ac_cv_func_malloc_0_nonnull=yes LIBS="$(CXXLIBS)" sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/iperf /bin/iperf
