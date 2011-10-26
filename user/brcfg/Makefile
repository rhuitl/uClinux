
EXEC = brcfg
OBJS = brcfg.o

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	rm -f $(EXEC) *.o *.gdb *.elf
