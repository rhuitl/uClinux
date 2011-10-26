
CFLAGS += -DNO_GETTEXT -DHAVE_ISC_READER -DDO_PRELOAD -DNO_TFTP

CFLAGS += -g -O2
ifndef CONFIG_IPV6
CFLAGS += -DNO_IPV6
endif
ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DETC_DIR=\"/etc/config\"
endif
ifdef CONFIG_PROP_STATSD_STATSD
CFLAGS += -DDO_STATS
endif
ifdef CONFIG_USER_DNSMASQ2_RESOLVE_AS_SERVER
CFLAGS += -DDO_RESOLVE_AS_SERVER
endif

EXTRA_OBJS = preload.o
export EXTRA_OBJS

all: 
	$(MAKE) -f Makefile all

clean :
	$(MAKE) -f Makefile clean

install : 
	$(MAKE) -f Makefile install

romfs:
	$(ROMFSINST) src/dnsmasq /bin/dnsmasq
