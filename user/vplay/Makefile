
EXEC1 = vplay
EXEC2 = vrec
EXEC3 = mixer

OBJS = vplay.o
OBJS3 = mixer.o

all: $(EXEC1) $(EXEC2) $(EXEC3)

$(EXEC1): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(EXEC2): $(EXEC1)
	ln -f $(EXEC1) $(EXEC2)

$(EXEC3): $(OBJS3)
	$(CC) $(LDFLAGS) -o $@ $(OBJS3) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_VPLAY_VPLAY /bin/vplay
	$(ROMFSINST) -e CONFIG_USER_VPLAY_VREC  /bin/vrec
	$(ROMFSINST) -e CONFIG_USER_VPLAY_MIXER /bin/mixer

clean:
	-rm -f $(EXEC1) $(EXEC2) $(EXEC3) *.elf *.gdb *.o
