
CFLAGS += -Wall
EXEC    = kendin-config
OBJS    = kendin-config.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -f $(EXEC) $(OBJS) *.gdb

romfs: $(EXEC)
	$(ROMFSINST) /bin/$(EXEC)

