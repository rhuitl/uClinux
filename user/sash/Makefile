
ifdef CONFIG_USER_SASH_SH
SH = sh
SHOBJS = sash.o cmds.o cmd_uclinux.o ls.o hexdump.o df.o free.o \
	hostname.o date.o
endif

ifdef CONFIG_USER_SASH_SHUTDOWN
SHUTDOWN = shutdown
SHUTDOWNOBJS = shutdown.o
endif

ifdef CONFIG_USER_SASH_REBOOT
REBOOT = reboot
REBOOTOBJS = reboot.o
endif

ifdef CONFIG_USER_SASH_PS
SHOBJS += ps.o
CFLAGS += -DCONFIG_USER_SASH_PS
endif

LIBSASH = libsash/libsash.a

ifdef CONFIG_USER_SASH_HISTORY
CFLAGS += -DCOMMAND_HISTORY
endif

all: $(SH) $(SHUTDOWN) $(REBOOT)

$(SH): $(SHOBJS) $(LIBSASH)
	$(CC) $(LDFLAGS) -o $@ $(SHOBJS) $(LIBSASH) $(LDLIBS$(LDLIBS_$@))

$(SHUTDOWN): $(SHUTDOWNOBJS) $(LIBSASH)
	$(CC) $(LDFLAGS) -o $@ $(SHUTDOWNOBJS) $(LIBSASH) $(LDLIBS)

$(REBOOT): $(REBOOTOBJS) $(LIBSASH)
	$(CC) $(LDFLAGS) -o $@ $(REBOOTOBJS) $(LIBSASH) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) -e CONFIG_USER_SASH_SH       /bin/sh
	$(ROMFSINST) -e CONFIG_USER_SASH_REBOOT /bin/reboot
	$(ROMFSINST) -e CONFIG_USER_SASH_SHUTDOWN /bin/shutdown

dummy_target:

$(LIBSASH): dummy_target
	$(MAKE) -C libsash

clean:
	-rm -f $(SH) $(SHUTDOWN) $(REBOOT) *.elf *.gdb *.o
	$(MAKE) -C libsash clean

