
all: build/Makefile
	$(MAKE) -C build

build/Makefile: makefile
	rm -rf build
	mkdir build
	( \
		cd build; \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" \
			sh ../configure $(CONFIGURE_OPTS) \
			--disable-dietlibc --enable-release \
			--with-configfile=/etc/config/ips.cfg \
			--enable-dependency-tracking \
			--with-username=root \
			; \
	)

romfs:
	$(ROMFSINST) build/src/ip-sentinel /bin/ip-sentinel

clean:
	rm -rf build

