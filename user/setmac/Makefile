-include ../user.mak

EXEC = setmac
OBJS = setmac.o

ifdef CONFIG_IXP400_ETH
ifndef CONFIG_IXP425_IXP_AS_ETH
CFLAGS += -DETHPREFIX=\"ixp\"
endif
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

