CONFOPTS=--with-ssl=$(STAGEDIR) --with-random=/dev/urandom --prefix=

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/src/stunnel /bin/stunnel
ifdef CONFIG_USER_FLATFSD_FLATFSD
	$(ROMFSINST) -s /etc/config /etc/stunnel
endif
