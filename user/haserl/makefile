
CONF_OPTS = --prefix=

all: build
	$(MAKE) -C build

build: makefile
	rm -rf build
	mkdir build
	(cd build; CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" ../configure $(CONFIGURE_OPTS) $(CONF_OPTS))

romfs:
	$(ROMFSINST) build/src/haserl /bin

clean:
	rm -rf build

