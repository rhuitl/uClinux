# Makefile for Snapgear distribution 

BASEOBJS = miniupnpd.o upnphttp.o upnpdescgen.o upnpsoap.o \
           upnpreplyparse.o minixml.o \
		   upnpredirect.o getifaddr.o daemonize.o upnpglobalvars.o \
		   options.o upnppermissions.o minissdp.o

LNXOBJS = linux/getifstats.o
NETFILTEROBJS = netfilter/iptcrdr.o
IPTABLESINC=../iptables/include
LINUXINC=../../linux-2.6.x/include

ALLOBJS = $(BASEOBJS) $(LNXOBJS) $(NETFILTEROBJS)


LIBS += ../iptables/libiptc/libiptc.a $(LDLIBS) -lpthread
CFLAGS += -DSECURE_COMPUTING -L ../../uClibc/lib/


TESTUPNPDESCGENOBJS = testupnpdescgen.o upnpdescgen.o

EXECUTABLES = miniupnpd testupnpdescgen

.PHONY:	all clean install depend

all:	$(EXECUTABLES)

clean:
	$(RM) $(BASEOBJS) $(LNXOBJS) $(EXECUTABLES) \
	testupnpdescgen.o netfilter/iptcrdr.o

romfs:
	$(ROMFSINST) miniupnpd /bin/miniupnpd
	
miniupnpd:	$(BASEOBJS) $(LNXOBJS) $(NETFILTEROBJS) $(LIBS) 
	$(CC) $(CFLAGS) $(BASEOBJS) $(LNXOBJS) $(NETFILTEROBJS) $(LIBS) -o $@

testupnpdescgen:	$(TESTUPNPDESCGENOBJS)

netfilter/iptcrdr.o: netfilter/iptcrdr.c
	$(CC) $(CFLAGS) -I$(IPTABLESINC) -I$(LINUXINC) -c -o $@ $<
	
# DO NOT DELETE

miniupnpd.o: config.h upnpglobalvars.h upnppermissions.h upnphttp.h
miniupnpd.o: upnpdescgen.h miniupnpdpath.h getifaddr.h daemonize.h upnpsoap.h
miniupnpd.o: options.h minissdp.h
upnphttp.o: upnphttp.h config.h upnpdescgen.h miniupnpdpath.h upnpsoap.h
upnpdescgen.o: upnpdescgen.h miniupnpdpath.h upnpglobalvars.h
upnpdescgen.o: upnppermissions.h config.h upnpdescstrings.h
upnpsoap.o: upnpglobalvars.h upnppermissions.h config.h upnphttp.h upnpsoap.h
upnpsoap.o: upnpreplyparse.h upnpredirect.h getifaddr.h getifstats.h
upnpreplyparse.o: upnpreplyparse.h minixml.h
minixml.o: minixml.h
upnpredirect.o: upnpredirect.h upnpglobalvars.h upnppermissions.h config.h
getifaddr.o: getifaddr.h
daemonize.o: daemonize.h
upnpglobalvars.o: upnpglobalvars.h upnppermissions.h config.h
options.o: options.h upnppermissions.h config.h upnpglobalvars.h
upnppermissions.o: config.h upnppermissions.h
minissdp.o: config.h upnpdescstrings.h miniupnpdpath.h upnphttp.h
minissdp.o: upnpglobalvars.h upnppermissions.h minissdp.h
linux/getifstats.o: getifstats.h
testupnpdescgen.o: upnpdescgen.h
upnpdescgen.o: upnpdescgen.h miniupnpdpath.h upnpglobalvars.h
upnpdescgen.o: upnppermissions.h config.h upnpdescstrings.h
