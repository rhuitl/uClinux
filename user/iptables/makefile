# Configure options.

CONFOPTS := --prefix= --disable-shared --enable-static
ifndef CONFIG_USER_IPTABLES_IPTABLES
CONFOPTS += --disable-ipv4
endif
ifndef CONFIG_USER_IPTABLES_IP6TABLES
CONFOPTS += --disable-ipv6
endif
ifdef CONFIG_IP_NF_QUEUE
CONFOPTS += --enable-libipq
endif

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
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IPTABLES build/iptables-static /bin/iptables
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IPTABLES -l /bin/iptables /bin/iptables-save
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IPTABLES -l /bin/iptables /bin/iptables-restore
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IP6TABLES build/ip6tables-static /bin/ip6tables
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IP6TABLES -l /bin/ip6tables /bin/ip6tables-save
	$(ROMFSINST) -e CONFIG_USER_IPTABLES_IP6TABLES -l /bin/ip6tables /bin/ip6tables-restore
