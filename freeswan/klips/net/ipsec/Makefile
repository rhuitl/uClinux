# Makefile for KLIPS kernel code
# Copyright (C) 1998, 1999, 2000,2001  Richard Guy Briggs.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.39 2002/01/17 04:39:40 rgb Exp $
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (ie not a .c file).
#
# Note 2! The CFLAGS definition is now in the main makefile...

ifndef TOPDIR
TOPDIR  := /usr/src/linux
endif

ifndef ARCH
ARCH = arch
endif

subdir-  := 
subdir-n := 
subdir-y :=
subdir-m :=

O_TARGET := ipsec.o
obj-y := ipsec_init.o ipsec_sa.o ipsec_radij.o radij.o
obj-y += ipsec_life.o ipsec_proc.o
obj-y += ipsec_tunnel.o ipsec_rcv.o sysctl_net_ipsec.o 
obj-y +=  pfkey_v2.o pfkey_v2_parser.o 
obj-$(CONFIG_IXP4XX_CRYPTO) += ipsec_glue_mbuf.o ipsec_glue.o ipsec_glue_desc.o

export-objs := radij.o

obj-$(CONFIG_IPSEC_ALG) +=ipsec_alg.o alg/ipsec_alg_static.o
export-objs += ipsec_alg.o
subdir-$(CONFIG_IPSEC_ALG) += alg

# 'override CFLAGS' should really be 'EXTRA_CFLAGS'
EXTRA_CFLAGS += -Ilibfreeswan -Ilibdes
ifeq ($(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION),2.4.2-2)
EXTRA_CFLAGS += -DREDHAT_BOGOSITY
endif
ifeq ($(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION),2.4.3-12)
EXTRA_CFLAGS += -DREDHAT_BOGOSITY
endif

ifdef CONFIG_IXP4XX_CRYPTO
ifdef CONFIG_CPU_IXP46X
IX_XSCALE_SW = $(ROOTDIR)/modules/ixp425/ixp400-2.1/ixp400_xscale_sw
OSAL_DIR     = $(ROOTDIR)/modules/ixp425/ixp400-2.1/ixp_osal
EXTRA_CFLAGS += \
	-I$(IX_XSCALE_SW)/src/include \
	-I$(OSAL_DIR)/ \
	-I$(OSAL_DIR)/os/linux/include/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ioMem/ \
	-I$(OSAL_DIR)/os/linux/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/os/linux/include/core/  \
	-I$(OSAL_DIR)/os/linux/include/platforms/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp425 \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp465 \
	-I$(OSAL_DIR)/os/linux/include/core/ \
	-I$(OSAL_DIR)/include/ \
	-I$(OSAL_DIR)/include/modules/ \
	-I$(OSAL_DIR)/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/include/modules/ioMem/ \
	-I$(OSAL_DIR)/include/platforms/ \
	-I$(OSAL_DIR)/include/platforms/ixp400/ \
	-D__ixp46X
else
EXTRA_CFLAGS += 	-I$(ROOTDIR)/modules/ixp425/ixp400-1.4/ixp400_xscale_sw/src/include
endif
EXTRA_CFLAGS +=		-I../../include/linux \
			-DUSE_IXP4XX_CRYPTO
endif

#ifeq ($(CONFIG_IPSEC_DEBUG),y)
#EXTRA_CFLAGS += -g
#endif

EXTRA_CFLAGS += $(KLIPSCOMPILE)
EXTRA_CFLAGS += -Wall
#EXTRA_CFLAGS += -Werror
#EXTRA_CFLAGS += -Wconversion 
#EXTRA_CFLAGS += -Wmissing-prototypes 
EXTRA_CFLAGS += -Wpointer-arith 
#EXTRA_CFLAGS += -Wcast-qual 
#EXTRA_CFLAGS += -Wmissing-declarations 
EXTRA_CFLAGS += -Wstrict-prototypes
#EXTRA_CFLAGS += -pedantic
#EXTRA_CFLAGS += -O3
#EXTRA_CFLAGS += -W
#EXTRA_CFLAGS += -Wwrite-strings 
#EXTRA_CFLAGS += -Wbad-function-cast

ifeq ($(ARCH),m68knommu)
CFLAGS_ipsec_sha1.o = -O1
endif

obj-$(CONFIG_IPSEC_ENC_3DES) += libdes/libdes.a
obj-$(CONFIG_IPSEC_AUTH_HMAC_MD5) += ipsec_md5c.o
obj-$(CONFIG_IPSEC_AUTH_HMAC_SHA1) += ipsec_sha1.o
obj-$(CONFIG_IPSEC_IPCOMP) += ipcomp.o zlib/zlib.a
subdir-$(CONFIG_IPSEC_IPCOMP) += zlib
subdir-$(CONFIG_IPSEC) += libfreeswan
obj-y += libfreeswan/libkernel.a

###
### Pre Rules.make
###
# undo O_TARGET, obj-y if no static
ifneq ($(CONFIG_IPSEC),y)
O_TARGET := 
ipsec_obj-y := $(obj-y)
obj-y :=
subdir-y :=
endif

# Define obj-m if modular ipsec 
ifeq ($(CONFIG_IPSEC),m)
obj-m += ipsec.o
endif


# These rules translate from new to old makefile rules
# Translate to Rules.make lists.
multi-used      := $(filter $(list-multi), $(obj-y) $(obj-m))
multi-objs      := $(foreach m, $(multi-used), $($(basename $(m))-objs))
active-objs     := $(sort $(multi-objs) $(obj-y) $(obj-m))
O_OBJS          := $(obj-y)
M_OBJS          := $(obj-m)
MIX_OBJS        := $(filter $(export-objs), $(active-objs))
OX_OBJS := $(export-objs)
SUB_DIRS := $(subdir-y)
ALL_SUB_DIRS := $(subdir-y) $(subdir-m)
MOD_SUB_DIRS := $(subdir-m)

#   dunno why, but some 2.2 setups may need explicit -DEXPORT_SYMTAB
#   uncomment next line if ipsec_alg.c compilation fails with
#   "parse error before `EXPORT_SYMTAB_not_defined'"  --Juanjo
# CFLAGS_ipsec_alg.o += -DEXPORT_SYMTAB
#

include $(TOPDIR)/Rules.make

###
### Post Rules.make
###
# for modular ipsec, no O_TARGET defined => define ipsec.o creation rules
ifeq ($(CONFIG_IPSEC),m)
ipsec.o : $(ipsec_obj-y)
	rm -f $@
	$(LD) $(LD_EXTRAFLAGS) -r $(ipsec_obj-y) -o $@
endif

$(ipsec_obj-y) $(obj-y) $(obj-m):  $(TOPDIR)/include/linux/config.h $(TOPDIR)/include/linux/autoconf.h

libdes/libdes.a:
	( cd libdes && $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' libdes.a )

libfreeswan/libkernel.a:
	$(MAKE) -C libfreeswan

zlib/zlib.a:
	$(MAKE) -C zlib

alg/ipsec_alg_static.o: dummy
	$(MAKE) -C alg CC='$(CC)' CFLAGS='$(CFLAGS)' ipsec_alg_static.o

clean:
	-rm -f *.o

tags TAGS: *.c *.h libfreeswan/*.c libfreeswan/*.h
	find . -name '*.[ch]' |xargs etags
	find . -name '*.[ch]' |xargs ctags

tar:
		tar -cvf /dev/f1 .

#
# $Log: Makefile,v $
# Revision 1.39  2002/01/17 04:39:40  rgb
# Take compile options from top level Makefile.inc
#
# Revision 1.38  2001/11/27 05:28:07  rgb
# Shut off -Werror until we figure out a graceful way of quieting down the
# pfkey_ops defined but not used complaint in the case of SMP in
# pfkey_v2.c.
#
# Revision 1.37  2001/11/27 05:10:15  rgb
# Added -Ilibdes and removed lib/des* symlinks.
#
# Revision 1.36  2001/11/26 09:23:47  rgb
# Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
#
# Revision 1.35.2.1  2001/09/25 02:17:50  mcr
# 	added ipsec_sa, ipsec_life, ipsec_proc.
# 	added -Werror to compile flags (see fix for zlib/zutil.h)
#
# Revision 1.3  2001/09/21 04:41:26  mcr
# 	actually, ipsec_proc.c and ipsec_life.c were never actually compiled.
#
# Revision 1.2  2001/09/21 04:11:33  mcr
# 	first compilable version.
#
# Revision 1.1.1.2  2001/09/17 01:17:52  mcr
#   snapshot 2001-09-16
#
# Revision 1.35  2001/09/07 22:09:12  rgb
# Quiet down compilation.
#
# Revision 1.34  2001/08/11 17:10:23  henry
# update bogosity stuff to cover RH7.1 update
#
# Revision 1.33  2001/06/14 19:35:07  rgb
# Update copyright date.
#
# Revision 1.32  2001/06/13 21:00:50  rgb
# Added a kludge to get around RedHat kernel version bogosity...
#
# Revision 1.31  2001/01/29 22:19:06  rgb
# Convert to 2.4 new style with back compat.
#
# Revision 1.30  2000/09/29 19:51:57  rgb
# Moved klips/net/ipsec/ipcomp_* to zlib/* (Svenning).
#
# Revision 1.29  2000/09/15 11:37:01  rgb
# Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
# IPCOMP zlib deflate code.
#
# Revision 1.28  2000/09/15 04:55:25  rgb
# Clean up pfkey object inclusion into the default object.
#
# Revision 1.27  2000/09/12 03:20:47  rgb
# Cleared out now unused pfkeyv2 switch.
# Enabled sysctl.
#
# Revision 1.26  2000/09/08 19:12:55  rgb
# Change references from DEBUG_IPSEC to CONFIG_IPSEC_DEBUG.
#
# Revision 1.25  2000/06/16 03:09:16  rgb
# Shut up cast lost warning due to changes in 2.4.0-test1.
#
# Revision 1.24  2000/03/16 06:40:48  rgb
# Hardcode PF_KEYv2 support.
#
# Revision 1.23  2000/02/14 21:10:38  rgb
# Added gcc debug flag when KLIPS_DEBUG is swtiched on.
#
# Revision 1.22  2000/01/21 09:44:29  rgb
# Added compiler switches to be a lot more fussy.
#
# Revision 1.21  1999/11/25 23:35:20  rgb
# Removed quotes to fix Alpha compile issues.
#
# Revision 1.20  1999/11/17 15:49:34  rgb
# Changed all occurrences of ../../../lib in pathnames to libfreeswan,
# which refers to the /usr/src/linux/net/ipsec/lib directory setup by the
# klink target in the top-level Makefile; and libdeslite.o to
# libdes/libdes.a.
# Added SUB_DIRS := lib definition for the kernel libraries.
#
# Revision 1.19  1999/04/27 19:06:47  rgb
# dd libs and dependancies to tags generation.
#
# Revision 1.18  1999/04/16 16:28:12  rgb
# Minor bugfix to avoid including DES if only AH is used.
#
# Revision 1.17  1999/04/15 15:37:23  rgb
# Forward check changes from POST1_00 branch.
#
# Revision 1.14.2.1  1999/03/30 17:29:17  rgb
# Add support for pfkey.
#
# Revision 1.16  1999/04/11 00:28:56  henry
# GPL boilerplate
#
# Revision 1.15  1999/04/06 04:54:25  rgb
# Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
# patch shell fixes.
#
# Revision 1.14  1999/02/18 16:50:45  henry
# update for new DES library
#
# Revision 1.13  1999/02/12 21:11:45  rgb
# Prepare for newer LIBDES (patch from P.Onion).
#
# Revision 1.12  1999/01/26 02:05:08  rgb
# Remove references to INET_GET_PROTOCOL.
# Removed CONFIG_IPSEC_ALGO_SWITCH macro.
# Change from transform switch to algorithm switch.
#
# Revision 1.11  1999/01/22 06:16:09  rgb
# Added algorithm switch code config option.
#
# Revision 1.10  1998/11/08 05:31:21  henry
# be a little fussier
#
# Revision 1.9  1998/11/08 05:29:41  henry
# revisions for new libdes handling
#
# Revision 1.8  1998/08/12 00:05:48  rgb
# Added new xforms to Makefile (moved des-cbc to des-old).
#
# Revision 1.7  1998/07/27 21:48:47  rgb
# Add libkernel.
#
# Revision 1.6  1998/07/14 15:50:47  rgb
# Add dependancies on linux config files.
#
# Revision 1.5  1998/07/09 17:44:06  rgb
# Added 'clean' and 'tags' targets.
# Added TOPDIR macro.
# Change module back from symbol exporting to not.
#
# Revision 1.3  1998/06/25 19:25:04  rgb
# Rearrange to support static linking and objects with exported symbol
# tables.
#
# Revision 1.1  1998/06/18 21:27:42  henry
# move sources from klips/src to klips/net/ipsec, to keep stupid
# kernel-build scripts happier in the presence of symlinks
#
# Revision 1.3  1998/04/15 23:18:43  rgb
# Unfixed the ../../libdes fix to avoid messing up Henry's script.
#
# Revision 1.2  1998/04/14 17:50:47  rgb
# Fixed to find the new location of libdes.
#
# Revision 1.1  1998/04/09 03:05:22  henry
# sources moved up from linux/net/ipsec
# modifications to centralize libdes code
#
# Revision 1.1.1.1  1998/04/08 05:35:02  henry
# RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
#
# Revision 0.5  1997/06/03 04:24:48  ji
# Added ESP-3DES-MD5-96
#
# Revision 0.4  1997/01/15 01:32:59  ji
# Added new transforms.
#
# Revision 0.3  1996/11/20 14:22:53  ji
# *** empty log message ***
#
