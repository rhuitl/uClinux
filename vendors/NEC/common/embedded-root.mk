# embedded-root.mk -- Makefile to produce embedded-root-fs kernels on
#	NEC platforms
#
#  Copyright (C) 2002,03  NEC Electronics Corporation
#  Copyright (C) 2002,03  Miles Bader <miles@gnu.org>
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Written by Miles Bader <miles@gnu.org>

include $(NEC_COMMON)/common.mk

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "root" -f $(ROMFSIMG) -d $(ROMFSDIR)
	 # Relink the kernel with the root file system embedded in the image.
	$(MAKE) -C $(ROOTDIR)/$(LINUXDIR) LINUX=$(IMAGE) ROOT_FS_IMAGE=$(ROMFSIMG)
