
all: build/build
	$(MAKE) -C build

build/build: Makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure --host=$(CROSS_COMPILE:-=))
	touch build/build

romfs:

clean:
	rm -rf build

