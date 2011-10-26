
EXEC   =  reiserfsck
OBJS   =  main.o pass0.o pass1.o pass2.o semantic.o pass4.o \
          lost+found.o ubitmap.o uobjectid.o ustree.o ufile.o check.o \
          check_tree.o journal.o info.o segments.o
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

