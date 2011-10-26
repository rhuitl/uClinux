
SMBMOUNT = smbmount
SMBUMOUNT = smbumount

CFLAGS += -DVERSION=\"2.0.1\"

all: $(SMBMOUNT) $(SMBUMOUNT)

$(SMBMOUNT): smbmount.o
	$(CC) $(LDFLAGS) -o $@ smbmount.o $(LDLIBS)

$(SMBUMOUNT): smbumount.o 
	$(CC) $(LDFLAGS) -o $@ smbumount.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_SMBMOUNT_SMBMOUNT  /bin/smbmount
	$(ROMFSINST) -e CONFIG_USER_SMBMOUNT_SMBUMOUNT /bin/smbumount

clean:
	-rm -f $(SMBMOUNT) $(SMBUMOUNT) *.elf *.gdb *.o

