
EXEC = rtc
OBJS = rtc.o

ifdef CONFIG_LIB_UC_LIBC_TIMEZONE
CFLAGS += -DINCLUDE_TIMEZONE
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

