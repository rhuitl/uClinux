# Makefile for ntpclient/adjtimex
#
# Makefile by Uwe Beutin, modified by John Williams
# 
# ntpclient by Larry Dolittle
#
# /home/uclinux/uClinux-dist/user/ntpclient/Makefile
	
EXEC1 = ntpclient
EXEC2 = adjtimex

OBJS1 = ntpclient.o phaselock.o
OBJS2 = adjtimex.o

CFLAGS += -D__USE_BSD
all: $(EXEC1) $(EXEC2)

$(EXEC1): $(OBJS1)
	$(CC) $(LDFLAGS) -o $@ $(OBJS1) $(LDLIBS$(LDLIBS_$@))

$(EXEC2): $(OBJS2)
	$(CC) $(LDFLAGS) -o $@ $(OBJS2) $(LDLIBS$(LDLIBS_$@))
romfs:
	$(ROMFSINST) -e CONFIG_USER_NTPCLIENT_NTPCLIENT /bin/$(EXEC1)
	$(ROMFSINST) -e CONFIG_USER_NTPCLIENT_ADJTIMEX /bin/$(EXEC2)
clean:
	rm -f $(EXEC1) $(EXEC2) *.gdb *.elf *.o

test: $(EXEC)
	./$(EXEC) -d -r < test.dat

