#
#	Makefile -- Build instructions for SecureComputing SG560-USB-Recover
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
FLASH     = $(IMAGEDIR)/flash.bin
BOOTLOADER = $(PRODUCTDIR)/../SG560U/SG560U_v4.1.0p0_20090216.sgb
IMAGESIZE = 3670016

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS) sda1

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,0 \
	tags,c,90,2 \
	log0,c,90,4 \
	log1,c,90,6 \
	kboot,c,90,8 \
	all,c,90,10

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc.static romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -p 550 /etc/mountflash
	$(ROMFSINST) -p 550 /etc/bootload
	$(ROMFSINST) -p 550 /etc/mkffs
	$(ROMFSINST) -p 550 /etc/rc.hd

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

image: image.configs image.dir image.arm.zimage image.squashfs image.bin image.size image.tag image.copy image.flash

#
# build up a flash.bin
#
vendor_flashbin:
	@cp $(ROOTDIR)/boot/boot.bin $(FLASH)
	@BOOTSIZE=`cat $(ROOTDIR)/boot/boot.bin | wc -c` ; \
	 PADSIZE=`expr 524288 - $$BOOTSIZE` ; \
	 dd if=/dev/zero bs=$$PADSIZE count=1 2> /dev/null | tr '\000' '\377' >> $(FLASH)
	@cat $(IMAGE) >> $(FLASH)
	@IMGSIZE=`cat $(FLASH) | wc -c` ; \
	 PADSIZE=`expr 4194304 - $$IMGSIZE` ; \
	 dd if=/dev/zero bs=$$PADSIZE count=1 2> /dev/null | tr '\000' '\377' >> $(FLASH)
	@echo "Factory `basename $(FLASH)` created."
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
