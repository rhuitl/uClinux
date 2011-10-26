
INCLUDES = -I.. -I../lib
NMALLOC = 

CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\" -D_BSD_SOURCE=1

FLTFLAGS += -s 32000

OBJS =  bgp_main.o bgpd.o bgp_fsm.o bgp_aspath.o bgp_community.o \
		bgp_attr.o bgp_debug.o bgp_route.o bgp_zebra.o bgp_open.o \
		bgp_routemap.o bgp_packet.o bgp_network.o bgp_filter.o bgp_regex.o \
		bgp_clist.o bgp_dump.o bgp_snmp.o bgp_ecommunity.o bgp_mplsvpn.o \
		bgp_table.o bgp_damp.o bgp_advertise.o bgp_vty.o bgp_nexthop.o

all: bgpd

bgpd: $(OBJS) $(NMALLOC) ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(NMALLOC) ../lib/libzebra.a \
			$(LIBCRYPT) $(LIBM) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) -e CONFIG_USER_ZEBRA_BGPD_BGPD /bin/bgpd

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.gdb *.elf *.o bgpd

dummy_target:

nfs: dummy_target
	@$(MAKE) MAKE_NFS=1

