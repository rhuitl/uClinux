# Configure options.

CONFOPTS := --prefix=

all: build/build
	$(MAKE) -C build

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/udev/udevd /sbin/udevd
	$(ROMFSINST) build/udev/udevadm /sbin/udevadm
	$(ROMFSINST) -d udev.conf /etc/udev/udev.conf
	$(ROMFSINST) -d -s /etc/config/udev.rules /etc/udev/rules.d/50-config.rules
	        	
