
SBIN = hwclock
CFLAGS += -DHAVE_locale_h -DHAVE_nanosleep


all: $(SBIN)

hwclock.o: hwclock.c shhopt.h
hwclock.o cmos.o rtc.o kd.o: clock.h
hwclock: hwclock.o shhopt.o cmos.o rtc.o kd.o

CWFLAGS := $(subst -Wmissing-prototypes,,$(CFLAGS))

cmos.o: cmos.c
	$(CC) $(CWFLAGS) -c cmos.c -o $@

clean:
	-rm -f *.o *~ core $(SBIN)

romfs:
	$(ROMFSINST) /bin/hwclock
