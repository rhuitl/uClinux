
CFLAGS += -DHAVE_CONFIG_H -DSYSCONFDIR=\"/etc/config/\"
CFLAGS += -I.. -I../lib -Wall

OBJS =  version.o network.o pid_output.o \
		daemon.o print_version.o checksum.o \
		vector.o linklist.o vty.o command.o sockunion.o \
		prefix.o thread.o if.o memory.o buffer.o buffer.o \
		table.o hash.o filter.o routemap.o distribute.o \
		stream.o str.o log.o plist.o zclient.o sockopt.o smux.o \
		md5.o keychain.o

all: libzebra.a

libzebra.a: $(OBJS)
	-rm -f libzebra.a
	$(AR) cru libzebra.a $(OBJS)
	$(RANLIB) libzebra.a

version.o: version.c

version.c: Makefile
	echo '' >version.c
	echo 'char *host_name = "$(host_alias)";' >>version.c

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

romfs:

clean: dummy_target
	-rm -f *.o libzebra.a version.c

dummy_target:

nfs: dummy_target
	$(MAKE) MAKE_NFS=1
