#
#	Makefile -- Build instructions for CyberGuard/SG300
#

ROMFSIMG      = $(IMAGEDIR)/ramdisk
ZIMAGE        = $(IMAGEDIR)/zImage
ZIMAGESIZE    = 786432
IMAGE         = $(IMAGEDIR)/image.bin
IMAGESIZE     = 3932160
SQUASH_ENDIAN = -le

ROMFS_DIRS    = $(DEFAULT_ROMFS_DIRS)

DEVICES      += $(DEVICE_PTY_64)

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.tag image.copy

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
