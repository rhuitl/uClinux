#
# build using configure as best we can, should work for most targets
# David McCullough <davidm@snapgear.com>
#

.PHONY: all
all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	chmod u+x configure
	( \
		cd build; \
		export CC="$(CC) $(CFLAGS)"; \
		export LDFLAGS="$(LDFLAGS)"; \
		export LIBS="$(LDLIBS)"; \
		sh ../configure $(CONFIGURE_OPTS) --prefix= ; \
	)

.PHONY: romfs
romfs:
	$(ROMFSINST) build/rtpproxy /bin/rtpproxy

.PHONY: clean
clean:
	rm -rf build

