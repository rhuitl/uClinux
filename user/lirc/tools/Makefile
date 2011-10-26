
PROGRAMS   = irexec irw mode2
# PROGRAMS += irxevent irpty smode2 xmode2
COMMON   = lirc_client.o
CC += -I..
FLTFLAGS += -s 32000

all: $(PROGRAMS)

irexec: $(COMMON) irexec.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

irpty: $(COMMON) irpty.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

irw: $(COMMON) irw.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

mode2: $(COMMON) mode2.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

smode2: $(COMMON) smode2.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

xmode2: $(COMMON) xmode2.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

irxevent: $(COMMON) irxevent.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(COMMON) $(LDLIBS)

clean:
	rm -f $(PROGRAMS) *.elf *.gdb *.o
