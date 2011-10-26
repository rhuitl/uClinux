
EXEC = dhcpcd
OBJS = arp.o client.o daemon.o error-handler.o hostinfo.o \
	if.o main.o memory.o options.o signal-handler.o socket-if.o \
	ip_nettel.o

CFLAGS += -D_BSD_SOURCE

ifdef BUILD_NETtel
CFLAGS += -DCONFIG_NETtel
endif
ifdef BUILD_NETtel1500
CFLAGS += -DCONFIG_NETtel
endif

ifdef CONFIG_USER_DHCPCD_LLIP
	CFLAGS += -DLLIP_SUPPORT
	OBJS += llip.o llip_utils.o udpipgen.o
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o

$(OBJS):	arp.h client.h daemon.h dhcp-options.h dhcp.h error-handler.h \
			hostinfo.h if.h memory.h signal-handler.h socket-if.h ip_nettel.h

