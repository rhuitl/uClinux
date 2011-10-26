# Uncomment this on Solaris.
#LIBS = -lsocket -lnsl

OBJS = cache.o rfc1035.o dhcp.o util.o option.o forward.o network.o dnsmasq.o
BINDIR = /usr/local/sbin
MANDIR = /usr/local/man

ifdef CONFIG_IPV6
CFLAGS += -DHAVE_IPV6
endif
ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DETC_DIR=\"/etc/config\"
endif

all : dnsmasq

clean :
	rm -f *~ */*~ $(OBJS) dnsmasq core 

.c.o: dnsmasq.h config.h
	$(CC) $(CFLAGS) $(RPM_OPT_FLAGS) -Wall -W -c $*.c 

dnsmasq : $(OBJS) dnsmasq.h config.h
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

install : dnsmasq
	install -d $(DESTDIR)$(BINDIR) -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	install -m 755 dnsmasq $(DESTDIR)$(BINDIR)

romfs:
	$(ROMFSINST) /bin/dnsmasq
