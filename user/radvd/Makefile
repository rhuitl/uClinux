
all: build/build
	$(MAKE) -C build

build/build: Makefile
	touch gram.y
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) etc /etc
	$(ROMFSINST) -e CONFIG_USER_RADVD_RADVD build/radvd /bin/radvd
	$(ROMFSINST) -e CONFIG_USER_RADVD_RADVD build/radvdump /bin/radvdump
