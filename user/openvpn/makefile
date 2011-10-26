CONFOPTS=--enable-password-save

CFLAGS := $(CFLAGS:-O1=)
CFLAGS := $(CFLAGS:-O2=)
CFLAGS := $(CFLAGS) -fno-inline

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
	$(ROMFSINST) build/openvpn /bin/openvpn
	$(ROMFSINST) sample-keys/dh1024.pem /etc/dh1024.pem
