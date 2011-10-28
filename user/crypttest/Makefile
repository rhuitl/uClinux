EXEC = test
OBJS += test.o
#OBJS += jpegsign.o
#OBJS += jpegdecode.o
#CFLAGS += -fno-common
LDFLAGS += -Wl,-v
CFLAGS += -g -O0

LDLIBS += -lcrypto

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o *.d
	
romfs:
	$(ROMFSINST) /bin/$(EXEC)

-include *.d
