
all: cube twist

cube: miker.o
	$(CC) $(LDFLAGS) -o $@ miker.o $(LDLIBS$(LDLIBS-$(@)))
twist: twist.o
	$(CC) $(LDFLAGS) -o $@ twist.o $(LDLIBS$(LDLIBS-$(@)))

romfs:
	$(ROMFSINST) /bin/cube
	$(ROMFSINST) /bin/twist

clean:
	-rm -f cube twist *.elf *.gdb *.o

