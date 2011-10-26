EXECS = cbi

USBCLIENT = cbi
CLIENTOBJS = cbi_desc.o cbi.o

all: $(USBCLIENT)

$(USBCLIENT): $(CLIENTOBJS)
	$(CC) $(LDFLAGS) -o $@ $(CLIENTOBJS) $(LDLIBS)
	$(CONVERT)

romfs:
	$(ROMFSINST) /bin/cbi

clean:
	-rm -f $(EXECS) *.elf *.gdb *.o
