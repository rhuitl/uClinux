
NMALLOC = 
INCLUDES = -I.. -I../lib

CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\"

OBJS    = rip_debug.o rip_interface.o rip_main.o rip_peer.o \
			rip_routemap.o rip_snmp.o rip_zebra.o ripd.o rip_offset.o

all: ripd

ripd: $(OBJS) $(NMALLOC) ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(NMALLOC) ../lib/libzebra.a $(LIBCRYPT) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_ZEBRA_RIPD_RIPD /bin/ripd

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.gdb *.elf *.o ripd

dummy_target:

nfs: dummy_target
	@$(MAKE) MAKE_NFS=1

