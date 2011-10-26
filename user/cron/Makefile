-include ../user.mak

EXEC = cron

all: $(EXEC)

cron: cron.o cron-parent.o bitstring.h Makefile
	$(CC) $(LDFLAGS) -o $@ cron.o cron-parent.o $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/cron

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
