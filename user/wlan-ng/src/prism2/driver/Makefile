# src/prism2/driver/Makefile
#
# Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
# --------------------------------------------------------------------
#
# linux-wlan
#
#   The contents of this file are subject to the Mozilla Public
#   License Version 1.1 (the "License"); you may not use this file
#   except in compliance with the License. You may obtain a copy of
#   the License at http://www.mozilla.org/MPL/
#
#   Software distributed under the License is distributed on an "AS
#   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
#   implied. See the License for the specific language governing
#   rights and limitations under the License.
#
#   Alternatively, the contents of this file may be used under the
#   terms of the GNU Public License version 2 (the "GPL"), in which
#   case the provisions of the GPL are applicable instead of the
#   above.  If you wish to allow the use of your version of this file
#   only under the terms of the GPL and not to allow others to use
#   your version of this file under the MPL, indicate your decision
#   by deleting the provisions above and replace them with the notice
#   and other provisions required by the GPL.  If you do not delete
#   the provisions above, a recipient may use your version of this
#   file under either the MPL or the GPL.
#
# --------------------------------------------------------------------
#
# Inquiries regarding the linux-wlan Open Source project can be
# made directly to:
#
# AbsoluteValue Systems Inc.
# info@linux-wlan.com
# http://www.linux-wlan.com
#
# --------------------------------------------------------------------
#
# Portions of the development of this software were funded by 
# Intersil Corporation as part of PRISM(R) chipset product development.
#
# --------------------------------------------------------------------

include $(WLAN_SRC)../../../config.mk

ifeq ($(WLAN_DEBUG), y)
WLAN_INCLUDE_DEBUG=-DWLAN_INCLUDE_DEBUG
endif

obj-m :=

ifeq ($(PRISM2_PCMCIA), y)
	obj-m += prism2_cs.o
endif

ifeq ($(PRISM2_PCI), y)
	obj-m += prism2_pci.o
endif

ifeq ($(PRISM2_PLX), y)
	obj-m += prism2_plx.o
endif

ifeq ($(PRISM2_USB), y)
	obj-m += prism2_usb.o
endif

ifneq ($(KERNELRELEASE),)

EXTRA_CFLAGS += -I$(WLAN_SRC)/../../include -I$(WLAN_SRC)/../include $(WLAN_INCLUDE_DEBUG)

ifeq ($(KERN_25), y)

else

include $(TOPDIR)/Rules.make

endif

else

PWD := $(shell pwd)

default:
ifeq ($(KERN_25), y)
	if test ! -d $(PWD)/../.tmp_versions; then \
		cp -rf $(LINUX_SRC)/.tmp_versions $(PWD)/../ ; \
	fi

	$(MAKEARCH_KERNEL) -C $(LINUX_SRC) SUBDIRS=$(PWD) WLAN_SRC=$(PWD)/ \
		MODVERDIR=$(PWD)/../.tmp_versions modules
else # kbuild 2.4

	$(MAKEARCH_KERNEL) -C $(LINUX_SRC) SUBDIRS=$(PWD) WLAN_SRC=$(PWD)/ \
		modules

endif # kbuild switch

endif  #KERNELRELEASE

clean:
	rm -f *.o *.ko .*.cmd *.mod.c  *.flags .*.flags

install:
ifeq ($(KERN_25), y)
	cp $(obj-m:.o=.ko)	$(TARGET_MODDIR)/linux-wlan-ng
else
	cp $(obj-m)	$(TARGET_MODDIR)/linux-wlan-ng
endif

romfs:
ifeq ($(KERN_25), y)
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNEL_RELEASE)/net
	$(ROMFSINST) $(obj-m:.o=.ko) /lib/modules/$(KERNEL_RELEASE)/net/
else
	mkdir -p $(ROMFSDIR)/lib/modules/$(KERNEL_RELEASE)/net
	$(ROMFSINST) $(obj-m) /lib/modules/$(KERNEL_RELEASE)/net/
endif
