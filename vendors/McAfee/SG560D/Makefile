#
#	Makefile -- Build instructions for McAfee SG560D
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
FLASH     = $(IMAGEDIR)/flash.bin
BOOTLOADER = $(PRODUCTDIR)/SG560D_v4.1.0p0_20090428.sgb

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS) sda1

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,0 \
	tags,c,90,2 \
	log0,c,90,4 \
	log1,c,90,6 \
	kboot,c,90,8 \
	kbootblock,b,31,4 \
	all,c,90,10

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

image: image.configs image.dir image.arm.zimage image.squashfs image.bin image.tag image.copy image.flash

#
# build up a flash.bin
#
vendor_flashbin:
	@cp $(ROOTDIR)/boot/boot.bin $(FLASH)
	@BOOTSIZE=`cat $(ROOTDIR)/boot/boot.bin | wc -c` ; \
	 PADSIZE=`expr 917504 - $$BOOTSIZE` ; \
	 dd if=/dev/zero bs=$$PADSIZE count=1 2> /dev/null | tr '\000' '\377' >> $(FLASH)
	@cat $(IMAGE) >> $(FLASH)
	@IMGSIZE=`cat $(FLASH) | wc -c` ; \
	 PADSIZE=`expr 8388608 - $$IMGSIZE` ; \
	 dd if=/dev/zero bs=$$PADSIZE count=1 2> /dev/null | tr '\000' '\377' >> $(FLASH)
	@echo "Factory `basename $(FLASH)` created."
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
