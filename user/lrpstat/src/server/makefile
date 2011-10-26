EXEC = lrpstat
OBJS = lrpStat.o

#CFLAGS += -DUSE_ISDN
CFLAGS += -DLOG

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
                                                                                
romfs:
	$(ROMFSINST) /bin/$(EXEC)
#	$(ROMFSINST) \
		-a "kdm stream tcp nowait root /bin/lrpstat" /etc/inetd.conf

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
