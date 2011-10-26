
srcdir   = $(ROOTDIR)/freeswan
ipsecdir = $(srcdir)/klips/net/ipsec

vpath %.c $(srcdir)/klips/utils

CFLAGS	+= -D__USE_BSD -I$(ipsecdir) -I$(srcdir)/lib -I$(srcdir)
CFLAGS	+= -Wall
#CFLAGS	+= -Wconversion
#CFLAGS	+= -Wmissing-prototypes
#CFLAGS	+= -Wpointer-arith
#CFLAGS	+= -Wcast-qual
#CFLAGS	+= -Wmissing-declarations
CFLAGS	+= -Wstrict-prototypes
#CFLAGS	+= -pedantic
#CFLAGS	+= -O3
#CFLAGS	+= -W
#CFLAGS	+= -Wwrite-strings
#CFLAGS	+= -Wbad-function-cast 

ALL=spi eroute spigrp tncfg klipsdebug

FREESWANLIB = ../lib/libfreeswan.a

#LIBGMP        = -lgmp

INSTALL=install

all: $(ALL)

constants.o : $(ROOTDIR)/freeswan/pluto/constants.c $(ROOTDIR)/freeswan/pluto/constants.h
	$(CC) $(CFLAGS) -c -o $@ $< 
	
alg_info.o : $(ROOTDIR)/freeswan/pluto/alg_info.c $(ROOTDIR)/freeswan/pluto/alg_info.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $<  
	
kernel_alg.o : $(ROOTDIR)/freeswan/pluto/kernel_alg.c $(ROOTDIR)/freeswan/pluto/kernel_alg.h
	$(CC) $(CFLAGS) -DNO_PLUTO -c -o $@ $< 
	
spi: spi.o constants.o alg_info.o kernel_alg.o
	$(CC) $(LDFLAGS) -o $@ $^ $(FREESWANLIB) $(LDLIBS)
#	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

eroute: eroute.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

spigrp: spigrp.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

tncfg: tncfg.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

klipsdebug: klipsdebug.o
	$(CC) $(LDFLAGS) -o $@ $? $(FREESWANLIB) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_SPI /bin/spi
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_EROUTE /bin/eroute
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_SPIGRP /bin/spigrp
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_TNCFG /bin/tncfg
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_KLIPS_KLIPSDEBUG /bin/klipsdebug

clean:
	rm -f *.elf *.gdb *.o $(ALL)

