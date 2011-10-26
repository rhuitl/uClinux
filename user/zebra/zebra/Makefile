
NMALLOC = 
INCLUDES = -I.. -I../lib

CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\" -DMULTIPATH_NUM=1

OBJS =  zserv.o main.o interface.o connected.o ioctl.o \
		redistribute.o debug.o rtadv.o zebra_snmp.o zebra_rib.o \
		zebra_vty.o
#OBJS += rt_ioctl.o
OBJS += if_ioctl.o
OBJS += if_proc.o
3OBJS += rtread_proc.o
OBJS += ipforward_proc.o
OBJS += rt_netlink.o  rtread_netlink.o

all: zebra

zebra: $(OBJS) $(NMALLOC) ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(NMALLOC) ../lib/libzebra.a $(LIBCRYPT) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/zebra

client : client_main.o ../lib/libzebra.a
	$(CC) $(LDFLAGS) -o $@ client_main.o ../lib/libzebra.a $(LDLIBS)

.c.o:
	$(CC) $(INCLUDES) $(CFLAGS) -c $<

clean:
	rm -f *.gdb *.elf *.o client zebra

dummy_target:

nfs: dummy_target
	@$(MAKE) MAKE_NFS=1

