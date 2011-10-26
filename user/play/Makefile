
EXEC1 = play
OBJS1 = play.o

EXEC2 = tone
OBJS2 = tone.o

all: $(EXEC1) $(EXEC2)

$(EXEC1): $(OBJS1)
	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS)

$(EXEC2): $(OBJS2)
	$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDLIBS) $(LIBM)

romfs:
	$(ROMFSINST) -e CONFIG_USER_PLAY_PLAY /bin/play
	$(ROMFSINST) -e CONFIG_USER_PLAY_TONE /bin/tone

clean:
	-rm -f $(EXEC1) $(EXEC2) *.elf *.gdb *.o

