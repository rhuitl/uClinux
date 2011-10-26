
EXEC = chat
OBJS = chat.o

ifdef CONFIG_USER_CHAT_CHAT_NETWORK
CFLAGS += -DENABLE_NETWORK_SUPPORT=1
endif

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

