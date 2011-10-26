#
#	Makefile -- Build instructions for SecureComputing SG720
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
MBRIMG    = $(IMAGEDIR)/mbr.img
BOOTLOADER = $(PRODUCTDIR)/SG720_v4.1.0p0_20090301.sgb

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS) boot

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,0 \
	tags,c,90,2 \
	log,c,90,4 \
	image,b,3,0 \
	config,b,3,2

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -e CONFIG_USER_LM_SENSORS_SENSORS sensors.conf /etc/sensors.conf

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

image: image.configs image.dir image.arm.zimage image.squashfs7z image.mbr image.bin image.tag image.copy

.PHONY: image.mbr

image.mbr: $(MBRIMG)

$(MBRIMG):
	$(DD) if=/dev/zero of=$@ bs=512 count=1
	printf "1,48575,L,*\n,,61,-\n" | /sbin/sfdisk  -uS -C 966 -H 16 -S 4 $@

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
