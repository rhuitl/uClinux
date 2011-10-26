EXECS = qspirx qspitest

all: qspi.o $(EXECS)

qspi.o:
	$(CC) $(CFLAGS) -c qspi.c

$(EXECS):
	$(CC) $(CFLAGS) -Wall $(LDFLAGS) -o $@ $@.c  qspi.o $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_QSPITEST_TEST  /bin/qspitest
	$(ROMFSINST) -e CONFIG_USER_QSPITEST_RX    /bin/qspirx

clean:
	rm -f $(EXECS) *.elf *.gdb *.[oa] *~ core 
