#
#	Makefile -- Build instructions for CyberGuard SG560
#

KERNELZ    = $(IMAGEDIR)/zImage
IMAGE      = $(IMAGEDIR)/image.bin
NETFLASH   = $(IMAGEDIR)/netflash.bin
ROMFSIMG  = $(IMAGEDIR)/ramdisk
ZIMAGE    = $(IMAGEDIR)/zImage
IMAGESIZE = 7733248
FLASH     = $(IMAGEDIR)/flash.bin

SQUASH_ENDIAN = -be

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,14 \
	ethmac,c,90,14 \
	bootarg,c,90,14 \
	config,c,90,4 \
	image,c,90,10 \
	recover,c,90,16\
	all,c,90,18

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode

#image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.size image.tag image.copy #image.flash

image: image.squashfs7z
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cat $(ROMFSIMG) $(KERNELZ) > $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	cp $(KERNELZ) $(NETFLASH)
	SIZE=`wc -c $(KERNELZ) | cut -d ' ' -f 1` ; \
	PAD=`expr 1572864 - $$SIZE` ; \
	dd if=/dev/zero count=1 bs=$$PAD >> $(NETFLASH) 2> /dev/null
	cat $(ROMFSIMG) >> $(NETFLASH)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(NETFLASH)
ifdef CONFIG_USER_NETFLASH_HMACMD5
	$(ROOTDIR)/user/netflash/hmacmd5 $(CONFIG_USER_NETFLASH_HMACMD5_KEY) \
		< $(NETFLASH) >> $(NETFLASH)
else
	$(ROOTDIR)/tools/cksum -b -o 2 $(NETFLASH) >> $(NETFLASH)
endif
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(NETFLASH) /tftpboot/netflash.bin
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/image.bin
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(KERNELZ) /tftpboot/
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(ROMFSIMG) /tftpboot/ramdisk
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
