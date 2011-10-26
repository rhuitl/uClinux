
EXEC = dhrystone
OBJS = dhry_1.o dhry_2.o

CFLAGS += -DNO_PROTOTYPES=1

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBM) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): dhry.h

