# Makefile for Linux 2.6 kbuild / Linux 2.4

# export-objs was removed in Linux 2.5.60
# export-objs := hostap.o ## hostap_crypt.o

obj-m += hostap.o hostap_crypt_wep.o hostap_crypt_tkip.o hostap_crypt_ccmp.o
## obj-m += hostap_crypt.o
obj-m += hostap_cs.o
obj-m += hostap_plx.o
obj-m += hostap_pci.o

ifeq ($(TOPDIR)/Rules.make,$(wildcard $(TOPDIR)/Rules.make))
# old build system (before 2.5.x)
include $(TOPDIR)/Rules.make

ifdef CONFIG_MODVERSIONS

VERFILES=hostap.ver ## hostap_crypt.ver
hostap_crypt_ccmp.o: $(VERFILES)
hostap_crypt_tkip.o: $(VERFILES)
hostap_crypt_wep.o: $(VERFILES)
hostap.o: $(VERFILES)
hostap_cs.o: $(VERFILES)
hostap_plx.o: $(VERFILES)
hostap_pci.o: $(VERFILES)
INCLUDES_MODVER=-include hostap.ver ## -include hostap_crypt.ver

GENKSYMS=/sbin/genksyms
ifdef CONFIG_SMP
        GENKSYMS += -p smp_
endif

## hostap_crypt.ver: hostap_crypt.c
##	$(CC) $(INCLUDES) $(CFLAGS) -E -D__GENKSYMS__ $^ | \
##		$(GENKSYMS) -k $(VERSION).$(PATCHLEVEL).$(SUBLEVEL) > $@
hostap.ver: hostap.c
	$(CC) $(INCLUDES) $(CFLAGS) -E -D__GENKSYMS__ $^ | \
		$(GENKSYMS) -k $(VERSION).$(PATCHLEVEL).$(SUBLEVEL) > $@

endif # CONFIG_MODVERSIONS
endif # old build system


# Need to add pcmcia-cs include path in the beginning of include directories.
# CFLAGS would add it to the end, so this need to use CC..
ifneq ($(PCMCIA_PATH),)
CC += -I$(PCMCIA_PATH)/include $(INCLUDES_MODVER)
endif
