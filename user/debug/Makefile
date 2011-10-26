EXEC = debug

OBJS = debug.o

$(EXEC): $(OBJS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
