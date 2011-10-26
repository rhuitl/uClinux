
INCLUDES = -I.. -I../lib
NMALLOC = 

CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\" -D_BSD_SOURCE=1

OBJS =  ospf_main.o ospfd.o ospf_zebra.o ospf_interface.o \
		ospf_ism.o ospf_neighbor.o ospf_nsm.o ospf_dump.o ospf_network.o \
		ospf_packet.o ospf_lsa.o ospf_spf.o ospf_route.o ospf_ase.o ospf_abr.o \
		ospf_ia.o ospf_flood.o ospf_lsdb.o ospf_asbr.o ospf_vty.o \
		ospf_routemap.o

all: ospfd

ospfd: $(OBJS) $(NMALLOC) ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(NMALLOC) ../lib/libzebra.a $(LIBCRYPT) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_ZEBRA_OSPFD_OSPFD /bin/ospfd

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.gdb *.elf *.o ospfd

dummy_target:

nfs: dummy_target
	@$(MAKE) MAKE_NFS=1

