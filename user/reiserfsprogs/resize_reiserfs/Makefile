
EXEC   =  resize_reiserfs
OBJS   =  do_shrink.o fe.o resize_reiserfs.o
CFLAGS += -I../include
LDADD  = ../lib/libmisc.a ../reiserfscore/libcore.a
FLTFLAGS += -s 16384

all: $(EXEC)

$(EXEC): $(OBJS) $(LDADD)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

