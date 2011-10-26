# Makefile -- Makefile for util-linux Linux utilities
# Created: Sat Dec 26 20:09:40 1992
# Revised: Fri Oct  6 21:02:21 1995 by r.faith@ieee.org
# Copyright 1992, 1993, 1994, 1995 Rickard E. Faith (faith@cs.unc.edu)
#
#include ../make_include
#include ../MCONFIG
VERSION=2.10m
FLTFLAGS+=-s 64000

TARGETS =
ifdef CONFIG_USER_FDISK_FDISK
TARGETS += fdisk
endif
ifdef CONFIG_USER_FDISK_SFDISK
TARGETS += sfdisk
endif

all: $(TARGETS)

fdisk: fdisk.o llseek.o fdiskbsdlabel.o fdisksgilabel.o fdisksunlabel.o \
	fdiskaixlabel.o i386_sys_types.o partname.o
fdisk.o: fdisk.c fdisk.h
fdiskbsdlabel.o: fdiskbsdlabel.c fdisk.h fdiskbsdlabel.h
fdisksunlabel.o: fdisksunlabel.c fdisksunlabel.h fdisk.h
fdiskaixlabel.o: fdiskaixlabel.c fdiskaixlabel.h fdisk.h
fdisk.o cfdisk.o sfdisk.o fdiskbsdlabel.o fdisksunlabel.o \
	fdisksgilabel.o fdiskaixlabel.o i386_sys_types.o partname.o: common.h
sfdisk: sfdisk.o i386_sys_types.o partname.o

.PHONY:	clean
clean:
	-rm -f *.o *~ core $(SBIN) *.elf *.gdb fdisk sfdisk

romfs:
	$(ROMFSINST) -e CONFIG_USER_FDISK_FDISK /bin/fdisk
	$(ROMFSINST) -e CONFIG_USER_FDISK_SFDISK /bin/sfdisk
