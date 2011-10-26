#
#	Makefile -- Build instructions for CyberGuard SG565
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
FLASH     = $(IMAGEDIR)/flash.bin

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -e CONFIG_MODULES_RALINK_RT61AP $(ROOTDIR)/modules/wireless/ralink-rt61ap/Module/RT2561S.bin /etc/RT2561S.bin

romfs.post:: romfs.ixp425-microcode romfs.no-ixp400-modules 

image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.tag image.copy image.flash

#
# build up a flash.bin
#
vendor_flashbin:
	@$(DD) conv=sync if=$(ROOTDIR)/boot/boot.bin of=$(FLASH) bs=256k 
	@cat $(IMAGE) >> $(FLASH)
	@echo "Factory `basename $(FLASH)` created."
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
