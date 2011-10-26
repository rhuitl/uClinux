PREFIX=/usr
LIBUPNP_PREFIX=/usr
#LIBIPTC_PREFIX=/usr

LIBS= $(LIBUPNP) $(LIBIXML) $(LIBTHREADUTIL) -lpthread
FILES= main.o gatedevice.o pmlist.o util.o config.o
CFLAGS += -Wall

ifdef HAVE_LIBIPTC
ifdef LIBIPTC_PREFIX
LIBS += -L$(LIBIPTC_PREFIX)/lib
INCLUDES += -I$(LIBIPTC_PREFIX)/include
endif

LIBS += -liptc
INCLUDES += -DHAVE_LIBIPTC
FILES += iptc.o
endif

all: upnpd

upnpd: $(FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(FILES) $(LIBS) -o $@ $(LDLIBS)
ifndef CONFIG_USER_LINUXIGD_DEFAULT
	cat etc/gatedesc.snapgear.in | sed -e 's/DEVICENAME\.IN/$(CONFIG_PRODUCT)/' > etc/gatedesc.snapgear
endif
	@echo "make $@ finished on `date`"

%.o:	%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm -f *.o upnpd
	rm -f etc/gatedesc.snapgear

install: upnpd
	install -d /etc/linuxigd
	install etc/gatedesc.xml /etc/linuxigd
	install etc/gateconnSCPD.xml  /etc/linuxigd
	install etc/gateicfgSCPD.xml /etc/linuxigd
	install etc/dummy.xml /etc/linuxigd
	install upnpd $(PREFIX)/sbin
	install upnpd.8 $(PREFIX)/share/man/man8
	if [ ! -f /etc/upnpd.conf ]; then install etc/upnpd.conf /etc; fi

romfs:
ifdef CONFIG_USER_LINUXIGD_LINUXIGD
	$(ROMFSINST) upnpd /bin/upnpd
	@if [ ! -d $(ROMFSDIR)/etc/linuxigd ]; then mkdir $(ROMFSDIR)/etc/linuxigd; fi
	$(ROMFSINST) etc/gateconnSCPD.xml /etc/linuxigd/gateconnSCPD.xml
	$(ROMFSINST) etc/gateicfgSCPD.xml /etc/linuxigd/gateicfgSCPD.xml
	$(ROMFSINST) etc/ligd.gif /etc/linuxigd/ligd.gif
	$(ROMFSINST) etc/dummy.xml /etc/linuxigd/dummy.xml
ifndef CONFIG_USER_LINUXIGD_DEFAULT
	$(ROMFSINST) etc/gatedesc.snapgear /etc/linuxigd/gatedesc.xml
else
	$(ROMFSINST) etc/gatedesc.xml /etc/linuxigd/gatedevice.xml
	$(ROMFSINST) etc/upnpd.conf /etc/default/upnpd.conf
endif
endif
