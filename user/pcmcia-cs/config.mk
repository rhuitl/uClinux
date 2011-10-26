LINUX=$(ROOTDIR)/$(LINUXDIR)
PREFIX=$(ROMFSDIR)
PCDEBUG=
USE_PM=y
#
# used to install modules
UTS_RELEASE=$(shell for TAG in VERSION PATCHLEVEL SUBLEVEL EXTRAVERSION ; do eval `sed -ne "/^$$TAG/s/[   ]//gp" $(LINUX)/Makefile`; done; echo $$VERSION.$$PATCHLEVEL.$$SUBLEVEL$$EXTRAVERSION)
MODDIR=/lib/modules/$(UTS_RELEASE)

# might want to check if this is needed
# SYSV_INIT is not defined

# CONFIG_SMP is not defined
# CONFIG_PCI is not defined
# CONFIG_PM is not defined
# CONFIG_SCSI is not defined
# CONFIG_IEEE1394 is not defined
CONFIG_INET=y
CONFIG_NET_PCMCIA_RADIO=y
# CONFIG_TR is not defined
# CONFIG_NET_FASTROUTE is not defined
# CONFIG_NET_DIVERT is not defined
# CONFIG_MODVERSIONS is not defined
# CONFIG_KERNEL_DEBUGGING is not defined
CONFIG_PROC_FS=y
# AFLAGS=
ifeq ($(ARCH),i386)
CONFIG_ISA=y
else
CONFIG_ISA=n
endif
CPPFLAGS=-I$(ROOTDIR)/$(LINUXDIR)/include -I../include

