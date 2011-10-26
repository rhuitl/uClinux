
EXEC = de2ts-cal
OBJS = de2ts-cal.o textdisplay.o
LDLIBS += $(LIBM)

CPPFLAGS += -DUSE_EEPROM=1

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS) $(LIBGCC)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
