# common.mk -- Common makefile fragment for NEC platform Makefiles
#
#  Copyright (C) 2002,03  NEC Electronics Corporation
#  Copyright (C) 2002,03  Miles Bader <miles@gnu.org>
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Written by Miles Bader <miles@gnu.org>

ROMFSIMG ?= $(IMAGEDIR)/root.romfs
IMAGE    ?= $(IMAGEDIR)/linux

# These are the only top-level dirs created for a `bootstrap' root filesystem
MINIMAL_ROMFS_DIRS = bin dev etc mnt proc

# These are all the top-level dirs created on a normal root filesystem
ROMFS_DIRS = $(MINIMAL_ROMFS_DIRS) var share home include lib

# These are the only device created for a `bootstrap' root filesystem
MINIMAL_DEVICES = \
	tty,c,5,0      console,c,5,1	null,c,1,3	zero,c,1,5

# These are all the devices on a normal root filesystem
DEVICES = \
	$(MINIMAL_DEVICES)						\
									\
	mem,c,1,1	kmem,c,1,2	random,c,1,8	urandom,c,1,9	\
									\
	ptyp0,c,2,0	ptyp1,c,2,1	ptyp2,c,2,2	ptyp3,c,2,3	\
	ptyp4,c,2,4	ptyp5,c,2,5	ptyp6,c,2,6	ptyp7,c,2,7	\
	ptyp8,c,2,8	ptyp9,c,2,9	ptypa,c,2,10	ptypb,c,2,11	\
	ptypc,c,2,12	ptypd,c,2,13	ptype,c,2,14	ptypf,c,2,15	\
									\
	ttyp0,c,3,0	ttyp1,c,3,1	ttyp2,c,3,2	ttyp3,c,3,3	\
	ttyp4,c,3,4	ttyp5,c,3,5	ttyp6,c,3,6	ttyp7,c,3,7	\
	ttyp8,c,3,8	ttyp9,c,3,9	ttypa,c,3,10	ttypb,c,3,11	\
	ttypc,c,3,12	ttypd,c,3,13	ttype,c,3,14	ttypf,c,3,15	\
									\
	$(PLATFORM_DEVICES)

all:

clean:

romfs:
	mkdir -p $(ROMFSDIR)
	if [ "$$CONFIG_NFSROOT" ]; then					\
	  ( cd $(ROMFSDIR); mkdir -p $(MINIMAL_ROMFS_DIRS) );		\
	  ( cd $(ROMFSDIR)/dev; touch $(MINIMAL_DEVICES:%=@%) );	\
	  (								\
	    echo '#!/bin/sh';						\
	    sh $(NEC_COMMON)/make-rc					\
	  ) > $(ROMFSDIR)/bin/init;					\
	  chmod +x $(ROMFSDIR)/bin/init;				\
	else								\
	  ( cd $(ROMFSDIR); mkdir -p $(ROMFS_DIRS) );			\
	  ( cd $(ROMFSDIR)/dev; touch $(DEVICES:%=@%) );		\
	  sh $(NEC_COMMON)/make-rc > $(ROMFSDIR)/etc/rc;		\
	  sh $(NEC_COMMON)/make-inittab > $(ROMFSDIR)/etc/inittab;	\
	  $(ROMFSINST) -s /var/tmp /tmp;				\
	  $(ROMFSINST) $(NEC_COMMON)/v850e/motd /etc/motd;		\
	  echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version;	\
	fi
	$(ROMFSINST) -s /bin /sbin
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) $(NEC_COMMON)/passwd /etc/passwd
	$(ROMFSINST) $(NEC_COMMON)/group /etc/group

# Note that the `image:' target is not defined here
