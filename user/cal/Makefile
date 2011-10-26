
CAL = cal
CALOBJS = cal.o

DATE = date
DATEOBJS = date.o

all: $(CAL) $(DATE)

$(CAL): $(CALOBJS)
	$(CC) $(LDFLAGS) -o $@ $(CALOBJS) $(LDLIBS)

$(DATE): $(DATEOBJS)
	$(CC) $(LDFLAGS) -o $@ $(DATEOBJS) $(LDLIBS)

romfs:
	[ "$(CONFIG_USER_CAL_CAL)" != y ] || cp cal $(ROMFSDIR)/bin/.
	[ "$(CONFIG_USER_CAL_DATE)" != y ] || cp date $(ROMFSDIR)/bin/.

clean:
	-rm -f $(CAL) $(DATE) *.elf *.gdb *.o

