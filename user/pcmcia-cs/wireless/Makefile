#
# Copyright (C) 1998 David A. Hinds -- dahinds@users.sourceforge.net
#
# Makefile 1.11 2001/07/03 01:55:57
#

# Include site dependent options and kernel configuration
include ../config.mk

# Don't remove "-O3" or bad things will happen!
CFLAGS := $(CPPFLAGS) $(CFLAGS) -O3
CPPFLAGS += $(PCDEBUG) -D__KERNEL__ -DMODULE
#CC = $(KCC) $(AFLAGS) $(KFLAGS)

XFLAGS = $(CFLAGS) $(MFLAG)

MODULES = netwave_cs.o wavelan_cs.o ray_cs.o wvlan_cs.o airo_cs.o airo.o
SRCS    = netwave_cs.c wavelan_cs.c ray_cs.c airo_cs.c airo.c \
	  wvlan_cs.c wvlan_hcf.c wvlan_hcfio.c \

all:	$(MODULES)

wvlan_hcf.o wvlan_hcfio.o: %.o: %.c
	$(CC) -MD -c $(XFLAGS) $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

wvlan_cs.o: wvlan_cs.c wvlan_hcf.o wvlan_hcfio.o
	$(CC) -c -MD $(CFLAGS) $(CPPFLAGS) $<
	@mkdir -p .depfiles ; mv $*.d .depfiles
	$(LD) -r -o .$@ $@ wvlan_hcf.o wvlan_hcfio.o
	mv .$@ $@ ; chmod -x $@

clean:
	rm -f core core.* *.o .*.o *.s *.a *~ .depend .depfiles/*.d

install: install-modules

include ../rules.mk
