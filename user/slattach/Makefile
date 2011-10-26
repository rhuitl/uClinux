
EXEC = slattach
OBJS = slattach.o pinger.o route.o

CFLAGS += -I../pppd.small/pppd

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBNETOLD) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o
