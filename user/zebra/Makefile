DIRS = lib zebra

ifdef CONFIG_USER_ZEBRA_BGPD_BGPD
DIRS += bgpd
endif

ifdef CONFIG_USER_ZEBRA_OSPFD_OSPFD
DIRS += ospfd
ifndef CONFIG_IP_MULTICAST
$(error CONFIG_IP_MULTICAST not defined)
endif
endif

ifdef CONFIG_USER_ZEBRA_RIPD_RIPD
DIRS += ripd
ifndef CONFIG_IP_MULTICAST
$(error CONFIG_IP_MULTICAST not defined)
endif
endif

all romfs: dummy_target
	for i in $(DIRS) ; do $(MAKE) -C $$i $@ || exit $? ; done

clean: dummy_target
	for i in $(DIRS) bgpd ospfd ripd ; do $(MAKE) -C $$i clean || exit $? ; done

dummy_target:

