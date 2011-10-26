
EXEC = rsyslogd
OBJS = rsyslogd.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

clean:
	rm -f $(EXEC) *.elf *.gdb *.o

romfs:
	$(ROMFSINST) /bin/$(EXEC)

