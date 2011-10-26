EXEC1 = no_oom
OBJS1 = no_oom.o

all: $(EXEC1)

$(EXEC1): $(OBJS1)
	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) -e CONFIG_USER_NOOOM_NOOOM /bin/$(EXEC1)

clean:
	rm -f $(EXEC1) *.elf *.gdb *.o
