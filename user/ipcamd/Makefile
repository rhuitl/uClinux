EXEC = ipcamd
OBJS += ipcamd.o
OBJS += jpegsign.o
OBJS += jpegdecode.o
OBJS += v4l2_control.o

LDLIBS += -lmicrohttpd -lpthread -ljpeg -lcrypto
CFLAGS += -MD -std=gnu99
#CFLAGS += -I../../lib/libmicrohttpd/src/include
#LDFLAGS += -L../../lib/libmicrohttpd/src/daemon/.libs

#all:
#	$(CC) $(CFLAGS) $(LDFLAGS) -std=gnu99 -o ipcamd ipcamd.c $(LDLIBS)

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o *.d
	
romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) /bin/dlipcamd
	$(ROMFSINST) /etc/private.pem

-include *.d
