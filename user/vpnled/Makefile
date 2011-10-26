.EXPORT_ALL_VARIABLES:

EXEC = vpnled
OBJS = main.o
CEES = main.c

all:
	make -f Makefile.NETtel

lin:
	make -f Makefile.Linux

elf:
	make -f Makefile.ELF

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o core

h:
	cfunctions -i -m *.c
debug:
	gcc -g -DMEMWATCH -DMW_STDIO $(CEES) -o ws
