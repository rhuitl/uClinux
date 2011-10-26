
EXEC := ferret
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

CFLAGS += -D__int64="long long" -DTRUE=1 -DFALSE=0
CFLAGS += -Dmemicmp=memcmp -Dstricmp=strcmp -D_snprintf=snprintf

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBPCAP) $(LDLIBS$(LDLIBS_$@))

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

