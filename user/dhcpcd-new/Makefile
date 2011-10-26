ifndef CONFIG_USER_DHCPCD_NEW_DHCPCD
# Not running under the uClinux build environment,
# so build a host version for debugging.
CFLAGS += -g -DHOSTBUILD -I../../include -DEMBED
endif

EXEC = dhcpcd
OBJS = arp.o buildmsg.o client.o dhcpcd.o peekfd.o signals.o udpipgen.o

ifeq ($(findstring 2.0,$(LINUXDIR)),2.0)
CFLAGS += -DOLD_LINUX_VERSION=1
endif
ifneq ($(CONFIG_LEDMAN),)
CFLAGS += -DCONFIG_LEDMAN
endif

CFLAGS += -D_BSD_SOURCE=1

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

