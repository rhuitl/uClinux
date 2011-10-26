
EXEC1   =  debugreiserfs
OBJS1   =  debugreiserfs.o pack.o

EXEC2   =  unpack
OBJS2   =  unpack.o

CFLAGS += -I../include
LDADD  = ../lib/libmisc.a ../reiserfscore/libcore.a
FLTFLAGS += -s 16384

all: $(EXEC1) $(EXEC2)

$(EXEC1): $(OBJS1) $(LDADD)
	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDADD) $(LDLIBS)

$(EXEC2): $(OBJS2) $(LDADD)
	$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDADD) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC1)
	$(ROMFSINST) /bin/$(EXEC2)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

