
EXECS = kill ps df shutdown free hostname reboot
OBJS = kill.o ps.o df.o shutdown.o free.o hostname.o reboot.o

all: $(EXECS)

$(EXECS): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $@.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_DF       /bin/df
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_FREE     /bin/free
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_HOSTNAME /bin/hostname
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_KILL     /bin/kill
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_PS       /bin/ps
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_REBOOT   /bin/reboot
	$(ROMFSINST) -e CONFIG_USER_SYSUTILS_SHUTDOWN /bin/shutdown

clean:
	rm -f $(EXECS) *.elf *.gdb *.o

