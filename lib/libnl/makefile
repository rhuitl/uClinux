CONFOPTS = --prefix=

all: build
	$(MAKE) -f Makefile

build: makefile
	./configure $(CONFIGURE_OPTS) $(CONFOPTS)
	touch build

clean:
	$(MAKE) -f Makefile clean
	rm -rf build

romfs:
	$(ROMFSINST) lib/libnl.so.1 /lib/libnl.so.1

