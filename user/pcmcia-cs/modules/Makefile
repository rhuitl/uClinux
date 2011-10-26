#
# Copyright (C) 2000 David A. Hinds -- dahinds@users.sourceforge.net
#
# Makefile 1.121 2001/07/03 01:55:58
#

# Include site dependent options and kernel configuration
include ../config.mk

# Don't remove "-O2" or bad things will happen!  We use -O2 rather
# than -O3 because it yields smaller code; this is not performance
# critical stuff.

CFLAGS := $(CPPFLAGS) $(CFLAGS) -O2
CPPFLAGS += $(PCDEBUG) -D__KERNEL__ -DMODULE
#CC = $(KCC) $(AFLAGS) $(KFLAGS)

SRCS    = cs.c cistpl.c rsrc_mgr.c bulkmem.c ds.c
CORE    = cs.o cistpl.o rsrc_mgr.o bulkmem.o
MODULES = pcmcia_core.o ds.o

ifdef CONFIG_PCMCIA
all:
	@echo "Your kernel is already configured with PCMCIA support."
else

ifdef CONFIG_CARDBUS
SRCS    += cardbus.c cb_enabler.c
CORE    += cardbus.o
MODULES += cb_enabler.o
endif

# Which socket drivers do we need?
ifeq ($(ARCH), arm)
SRCS	+= sa1100.c
MODULES	+= sa1100.o
else
ifdef CONFIG_8xx
SRCS	+= m8xx_pcmcia.c
MODULES	+= m8xx_pcmcia.o
else
SRCS	+= i82365.c tcic.c
MODULES	+= i82365.o tcic.o
endif
endif

ifdef CONFIG_PCI
SRCS    += pci_fixup.c
CORE    += pci_fixup.o
endif

ifdef CONFIG_PNP_BIOS
SRCS    += pnp_bios.c pnp_proc.c pnp_rsrc.c
CORE    += pnp_bios.o pnp_proc.o pnp_rsrc.o
endif

all:	$(MODULES)

pcmcia_core.o: $(CORE)
	$(LD) -r -o $@ $(CORE)
	chmod -x $@

install: install-modules

include ../rules.mk

endif

clean:
	rm -f core core.* *.o .*.o *.s *.a *~ .depend .depfiles/*.d
