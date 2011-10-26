# Makefile -- Build instructions for simulator NEC V850E processor under gdb
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

# Note -- the name `rootfs.image' matches the name of the file that the
# simulator-specific code in the kernel tries to read in at runtime; if you
# change it, you must also change the name in `arch/v850/kernel/sim.c'.
ROMFSIMG = $(IMAGEDIR)/rootfs.image
# similarly, the name of the kernel image is hardwired into the .gdbinit file
# that gets copied into the images directory.
IMAGE    = $(IMAGEDIR)/linux

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	cp $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)
	genromfs -v -V "root" -f $(ROMFSIMG) -d $(ROMFSDIR)
	 # Make a .gdbinit in the `images' subdir that starts the simulator 
	cp $(ROOTDIR)/$(LINUXDIR)/arch/v850/sim/gdb-scripts/example.gdbinit \
	   $(IMAGEDIR)/.gdbinit
