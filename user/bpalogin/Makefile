.EXPORT_ALL_VARIABLES:

EXEC = bpalogin
OBJS = bpalogin.o protocol.o transaction.o gen_md5.o unixmain.o

FLTFLAGS += -s 8192


all:
	make -f Makefile.NETtel

elf:
	make -f Makefile.ELF

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	rm -fr *.o *.elf *.gdb $(EXEC)
	
lin:
	make -f Makefile.linux

$(OBJS): bpalogin.h

