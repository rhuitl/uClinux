EXEC = snmpd
OBJS = snmpd.o

CFLAGS += -I../snmplib -I../modules

# Need a bigger stack than the default
FLTFLAGS += -s 8000

USELIBS = ../modules/libmodules.a ../snmplib/libsnmplib.a

all: $(EXEC)

test:

$(EXEC): $(OBJS) $(USELIBS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(USELIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.gdb *.elf *.o
