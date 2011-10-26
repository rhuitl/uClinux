#
# uClinux-dist makefile for quagga
# davidm@snapgear.com
#

CONFOPTS =
CONFOPTS += --prefix=
CONFOPTS += --sbindir=/bin
CONFOPTS += --program-transform-name=
CONFOPTS += --disable-user --disable-group

ifndef CONFIG_USER_QUAGGA_ZEBRA_ZEBRA
CONFOPTS += --disable-zebra
endif
ifndef CONFIG_USER_QUAGGA_BGPD_BGPD
CONFOPTS += --disable-bgpd
endif
ifndef CONFIG_USER_QUAGGA_RIPD_RIPD
CONFOPTS += --disable-ripd
endif
ifndef CONFIG_USER_QUAGGA_RIPNGD_RIPNGD
CONFOPTS += --disable-ripngd
endif
ifndef CONFIG_USER_QUAGGA_OSPFD_OSPFD
CONFOPTS += --disable-ospfd
endif
ifndef CONFIG_USER_QUAGGA_OSPF6D_OSPF6D
CONFOPTS += --disable-ospf6d
endif
ifndef CONFIG_USER_QUAGGA_WATCHQUAGGA_WATCHQUAGGA
CONFOPTS += --disable-watchquagga
endif
ifdef CONFIG_USER_QUAGGA_ISISD_ISISD
CONFOPTS += --enable-isisd
endif

CONFOPTS += --disable-shared
# CONFOPTS += --disable-static

ifdef CONFIG_USER_FLATFSD_FLATFSD
CONFOPTS += --sysconfdir=/etc/config
else
CONFOPTS += --sysconfdir=/etc
endif

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
	$(MAKE) -C build install DESTDIR=`pwd`/build/install
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_BGPD_BGPD \
			build/install/bin/bgpd   /bin/bgpd
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_OSPFD_OSPFD \
			build/install/bin/ospfd   /bin/ospfd
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_OSPF6D_OSPF6D \
			build/install/bin/ospf6d   /bin/ospf6d
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_RIPD_RIPD \
			build/install/bin/ripd   /bin/ripd
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_RIPNGD_RIPNGD \
			build/install/bin/ripngd   /bin/ripngd
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_WATCHQUAGGA_WATCHQUAGGA \
			build/install/bin/watchquagga /bin/watchquagga
	$(ROMFSINST) -e CONFIG_USER_QUAGGA_ZEBRA_ZEBRA \
			build/install/bin/zebra /bin/zebra

