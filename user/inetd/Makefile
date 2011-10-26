-include ../user/mak

SERVICES =    \"/etc/services\"
INETD_CONF =  \"/etc/inetd.conf\"

EXEC = inetd
OBJS = inetd.o config.o

CFLAGS += -DSERVICES=$(SERVICES) -DINETD_CONF=$(INETD_CONF)
CFLAGS += -Wall

# These changes allow for an additional, optional config file in /etc/config/inetd.conf
# which can be modified
CFLAGS += -DMODIFY_CONFIG -DALT_INETD_CONF=\"/etc/config/inetd.conf\"

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

clean:
	rm -f $(EXEC) *.elf *.gdb *.o

romfs:
	$(ROMFSINST) /bin/$(EXEC)

