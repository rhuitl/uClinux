CONFOPTS =

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../../../user/gdb/libiberty/configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
