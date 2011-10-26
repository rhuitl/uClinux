#
#	Makefile -- Build instructions for CyberGuard SG560
#

ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGE     = $(IMAGEDIR)/image.bin
IMAGESIZE = 7602176
FLASH     = $(IMAGEDIR)/flash.bin
BOOTLOADER= $(PRODUCTDIR)/SG560_v4.1.0p0_20090301.sgb

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,0 \
	ethmac,c,90,0 \
	bootarg,c,90,0 \
	tags,c,90,0 \
	config,c,90,2 \
	image,c,90,4 \
	all,c,90,6 \
	log,c,90,8

# IPSec is rather large and the 560 doesn't have much free RAM, so add it to the netflash kill list
NETFLASH_KILL_LIST_$(CONFIG_USER_FREESWAN)	+= pluto
NETFLASH_KILL_LIST_$(CONFIG_USER_OPENSWAN)	+= pluto

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) ../statsd.init.min /etc/statsd.init
	$(ROMFSINST) ../pam.init.min /etc/pam.init

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.size image.tag image.copy image.flash

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
