#
# Copyright (C) 1998 David A. Hinds -- dahinds@users.sourceforge.net
#
# Makefile 1.137 2001/07/03 01:55:57
#

# Include site dependent options and kernel configuration
include ../config.mk

# For files in kernel source tree, so that we can override config flags
XFLAGS := $(CPPFLAGS) $(CFLAGS) -O2 -D__KERNEL__ -DEXPORT_SYMTAB $(MFLAG)

# Don't remove "-O3" or bad things will happen!
CFLAGS := $(CPPFLAGS) $(CFLAGS) -O3
CPPFLAGS += $(PCDEBUG) -D__KERNEL__ -DMODULE
#CC = $(KCC) $(AFLAGS) $(KFLAGS)

SRCS    = serial_cs.c memory_cs.c ftl_cs.c dummy_cs.c \
	  sram_mtd.c iflash2_mtd.c iflash2+_mtd.c
MODULES = serial_cs.o memory_cs.o ftl_cs.o dummy_cs.o \
	  sram_mtd.o iflash2_mtd.o iflash2+_mtd.o
EXTRA   =
I_EXTRA =

ifdef CONFIG_CARDBUS
SRCS    += memory_cb.c serial_cb.c
MODULES += memory_cb.o serial_cb.o
ifdef CONFIG_INET
SRCS    += 3c575_cb.c tulip_cb.c epic_cb.c eepro100_cb.c
MODULES += 3c575_cb.o tulip_cb.o epic_cb.o eepro100_cb.o
endif
ifdef CONFIG_SCSI
ifdef DO_APA1480
SRCS    += apa1480_stub.c aic7xxx.c
MODULES += apa1480_cb.o
AIC7XXX  = aic7xxx.o
ifdef NEW_AIC7XXX
SRCS    += aic7xxx_linux.c aic7xxx_linux_pci.c aic7xxx_proc.c \
	   aic7770_linux.c aic7xxx_pci.c aic7xxx_93cx6.c aic7770.c
AIC7XXX += aic7xxx_linux.o aic7xxx_linux_pci.o aic7xxx_proc.o \
	   aic7770_linux.o aic7xxx_pci.o aic7xxx_93cx6.o aic7770.o
endif
endif
endif
ifdef CONFIG_IEEE1394
SRCS    += pcilynx_stub.c pcilynx.c ohci1394_stub.c ohci1394.c
MODULES += pcilynx_cb.o ohci1394_cb.o
endif
endif

ifdef CONFIG_INET
MODULES += pcnet_cs.o 3c589_cs.o nmclan_cs.o fmvj18x_cs.o smc91c92_cs.o \
	   xirc2ps_cs.o 3c574_cs.o axnet_cs.o
SRCS    += pcnet_cs.c 3c589_cs.c nmclan_cs.c fmvj18x_cs.c smc91c92_cs.c \
	   xirc2ps_cs.c 3c574_cs.c axnet_cs.c
SRCS    += 8390.c
EXTRA   += 8390.o
I_EXTRA += install-8390
ifdef CONFIG_TR
MODULES += ibmtr_cs.o
SRCS    += ibmtr_cs.c
endif
endif

ifdef DO_IDE
SRCS    += ide_cs.c
MODULES += ide_cs.o
endif

ifdef DO_PARPORT
SRCS    += parport_cs.c
MODULES += parport_cs.o
endif

vpath %.c $(LINUX)/drivers/net $(LINUX)/drivers/scsi \
	$(LINUX)/drivers/net/tokenring $(LINUX)/drivers/ieee1394 \
	$(LINUX)/drivers/scsi/aic7xxx

SCSI=$(LINUX)/drivers/scsi

ifdef CONFIG_SCSI
SRCS    += qlogicfas.c aha152x.c fdomain.c
SRCS    += qlogic_stub.c aha152x_stub.c fdomain_stub.c
MODULES += qlogic_cs.o aha152x_cs.o fdomain_cs.o
endif

all:	$(MODULES) $(EXTRA)

8390.o: 8390.c
	$(CC) -MD -c $(XFLAGS) -DMODULE $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

ibmtr_cs.o: ibmtr_cs.c ibmtr.o
	$(CC) -c -MD $(CFLAGS) $(CPPFLAGS) $<
	@mkdir -p .depfiles ; mv $*.d .depfiles
	$(LD) -r -o .$@ $@ ibmtr.o
	mv .$@ $@ ; chmod -x $@

ibmtr.o qlogicfas.o aha152x.o fdomain.o: %.o: %.c
	$(CC) -MD -c $(XFLAGS) -DPCMCIA -D__NO_VERSION__ $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

qlogic_cs.o: qlogic_stub.o qlogicfas.o
	$(LD) -r -o $@ $+ ; chmod -x $@

aha152x_cs.o: aha152x_stub.o aha152x.o
	$(LD) -r -o $@ $+ ; chmod -x $@

fdomain_cs.o: fdomain_stub.o fdomain.o
	$(LD) -r -o $@ $+ ; chmod -x $@

3c575_cb.o tulip_cb.o epic_cb.o eepro100_cb.o: %.o: %.c
	$(CC) -MD -c $(XFLAGS) -DMODULE -DCARDBUS $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

$(AIC7XXX) pcilynx.o ohci1394.o: %.o: %.c
	$(CC) -MD -c $(XFLAGS) -DPCMCIA -D__NO_VERSION__ $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

apa1480_cb.o: apa1480_stub.o $(AIC7XXX)
	$(LD) -r -o $@ $+ ; chmod -x $@

pcilynx_cb.o: pcilynx_stub.o pcilynx.o
	$(LD) -r -o $@ $+ ; chmod -x $@

ohci1394_cb.o: ohci1394_stub.o ohci1394.o
	$(LD) -r -o $@ $+ ; chmod -x $@

clean:
	rm -f core core.* *.o .*.o *.s *.a *~ .depend .depfiles/*.d

install-8390: 8390.o
	@mkdir -p $(PREFIX)$(MODDIR)/net
	@rm -f $(PREFIX)$(MODDIR)/net/8390.o
	cp 8390.o $(PREFIX)$(MODDIR)/net

install: install-modules $(I_EXTRA)

include ../rules.mk
