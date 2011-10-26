
KERNELSRC = $(ROOTDIR)/$(LINUXDIR)/.
export KERNELSRC

OSFLAGS = -DLINUX -I$(KERNELSRC)/include/
export OSFLAGS

ifdef CONFIG_USER_FLATFSD_FLATFSD
OSFLAGS += -DPPPD='"/bin/pppd"'
endif

# only enable kernel mode on 2.6 systems
ifdef CONFIG_PPPOL2TP
OSFLAGS += -DUSE_KERNEL
endif

all clean:
	$(MAKE) -f Makefile $@

romfs:
	$(MAKE) -f Makefile $@

