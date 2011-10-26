
all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" \
		sh ../configure $(CONFIGURE_OPTS) \
	)

romfs:
	$(ROMFSINST) build/src/grep /bin/grep
	$(ROMFSINST) -s /bin/grep /bin/egrep
	$(ROMFSINST) -s /bin/grep /bin/fgrep

clean:
	rm -rf build

