
EXEC = morse button latch r2100

all: $(EXEC)

morse: morse.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))
button: button.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))
latch: latch.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))
#meter: meter.o
#	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))
r2100: r2100.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) -e CONFIG_USER_DEMO_MORSE /bin/morse
	$(ROMFSINST) -e CONFIG_USER_DEMO_MORSE \
		-a "morse:unknown:/bin/morse" /etc/inittab
	$(ROMFSINST) -e CONFIG_USER_DEMO_BUTTON /bin/button
	$(ROMFSINST) -e CONFIG_USER_DEMO_BUTTON \
		-a "isakmp  stream tcp nowait root /bin/button" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_DEMO_R2100 /bin/r2100
	$(ROMFSINST) -e CONFIG_USER_DEMO_R2100 \
		-a "saft    stream tcp nowait root /bin/r2100" /etc/inetd.conf
	$(ROMFSINST) -e CONFIG_USER_DEMO_LATCH /bin/latch
	$(ROMFSINST) -e CONFIG_USER_DEMO_LATCH \
		-a "photuris stream tcp nowait root /bin/latch" /etc/inetd.conf

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

