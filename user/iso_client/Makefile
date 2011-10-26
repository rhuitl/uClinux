EXECS = iso

USBCLIENT = iso
CLIENTOBJS = iso_desc.o iso.o

all: $(USBCLIENT)

$(USBCLIENT): $(CLIENTOBJS)
	$(CC) $(LDFLAGS) -o $@ $(CLIENTOBJS) $(LDLIBS)
	$(CONVERT)

romfs:
	$(ROMFSINST) /bin/iso

clean:
	-rm -f $(EXECS) *.elf *.gdb *.o
