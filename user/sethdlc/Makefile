all: sethdlc

sethdlc: sethdlc.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/sethdlc

clean:
	-rm -f sethdlc *.elf *.gdb *.o
