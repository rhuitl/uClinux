CONFOPTS=--bindir=/bin --datadir=/etc 

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
	$(ROMFSINST) -e CONFIG_USER_HTTPTUNNEL_CLIENT build/htc /bin/htc
	$(ROMFSINST) -e CONFIG_USER_HTTPTUNNEL_SERVER build/hts /bin/hts
