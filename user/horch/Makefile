# Make some example applications using can4linux device driver
# (c) 2003 port GmbH oe@port.de
#

EXEC = horch
OBJS = horch.o linux.o filter.o version.o

# Used release tag for this software version
VERSION=2
REL=6
RELEASE=HORCH_$(VERSION)_$(REL)

CFLAGS += -I. -I ../../linux-2.4.x/drivers/char/can4linux
CFLAGS += -Wall

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS$(LDLIBS-$(@)))
	exit


clean:
	rm -f $(EXEC) *.elf *.gdb *.o

romfs:
	$(ROMFSINST) /bin/horch

version.c:	Makefile
	@echo "/* version file for horch, created by make */"   > $@
	@echo "char const horch_revision[] = \"$(VERSION).$(REL)$(PATCH)\";" >> $@
