
EXEC = readprofile
OBJS = readprofile.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) $(ROOTDIR)/$(LINUXDIR)/System.map /System.map

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

