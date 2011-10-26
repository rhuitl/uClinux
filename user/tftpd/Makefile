
EXEC = tftpd
OBJS = tftpd.o tftpsubs.o

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)
	$(ROMFSINST) -e CONFIG_USER_TFTPD_TFTPD \
	   	-a "tftp    dgram  udp wait   root /bin/tftpd" /etc/inetd.conf


clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

