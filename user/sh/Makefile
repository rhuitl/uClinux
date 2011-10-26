# Makefile for sh

EXEC = sh
OBJS = sh1.o sh2.o sh3.o sh4.o sh5.o sh6.o
CFLAGS += -DHAVE_MALLOC
FLTFLAGS += -s 8192

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS_$@))

romfs:
	$(ROMFSINST) /bin/$(EXEC)

$(OBJS): sh.h

clean:
	rm -f $(EXEC) *.elf *.gdb *.o
