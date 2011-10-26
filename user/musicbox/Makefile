
all: musicbox

musicbox: musicbox.o
	$(CC) -Wall $(LDFLAGS) -o $@ musicbox.o $(LDLIBS)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/musicbox

clean:
	-rm -f musicbox *.elf *.gdb *.o

