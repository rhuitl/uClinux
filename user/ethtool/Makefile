
all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" ../configure --host=$(TARGETARCH))

romfs:
	$(ROMFSINST) build/ethtool /bin/ethtool

clean:
	rm -rf build

