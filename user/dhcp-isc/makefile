
DHCP_ISC_CFLAGS         = $(filter-out -fno-common,$(CFLAGS))
DHCP_ISC_CONF_ENV       = ac_cv_file__dev_random=yes
DHCP_ISC_CONF_OPTS      =
ifndef CONFIG_IPV6
DHCP_ISC_CONF_OPTS      += --disable-dhcpv6
endif

all: build/Makefile 
	$(MAKE) -C build all 

build/Makefile: makefile
	mkdir -p build
	(cd build; $(DHCP_ISC_CONF_ENV) sh ../configure $(CONFIGURE_OPTS) $(DHCP_ISC_CONF_OPTS) CFLAGS="$(DHCP_ISC_CFLAGS)" )

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_DHCP_ISC_CLIENT_DHCLIENT  build/client/dhclient /bin/dhclient
	$(ROMFSINST) -e CONFIG_USER_DHCP_ISC_RELAY_DHCRELAY   build/relay/dhcrelay  /bin/dhcrelay
	$(ROMFSINST) -e CONFIG_USER_DHCP_ISC_SERVER_DHCPD     build/server/dhcpd    /bin/dhcpd
