
EXEC = telnet
OBJS = authenc.o commands.o main.o network.o ring.o sys_bsd.o telnet.o \
	terminal.o tn3270.o utilities.o genget.o getent.o misc.o

CFLAGS += -DPARANOID_TTYS -DTERMCAP -DUSE_TERMIO -DKLUDGELINEMODE -D_GNU_SOURCE

all: $(EXEC)

#uses non LGPL librarys
$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lg $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

$(OBJS): defines.h externs.h fdset.h general.h types.h ring.h misc.h \
		misc-proto.h

