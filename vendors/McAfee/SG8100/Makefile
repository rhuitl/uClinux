#
#	Makefile -- Build instructions for McAfee/SG8100
#

ZIMAGE     = $(IMAGEDIR)/zImage
CRAMFSIMG  = $(IMAGEDIR)/cramfs.img
JFFS2IMG   = $(IMAGEDIR)/jffs2.img
IMAGE      = $(IMAGEDIR)/image.bin
RECOVER    = $(IMAGEDIR)/recover.bin

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	boot,c,90,14 \
	tags,c,90,12 \
	config,c,90,4 \
	image,c,90,10 \
	recover,c,90,16 \
	all,c,90,18

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

romfs.post:: romfs.no-ixp400-modules romfs.ixp425-microcode
	$(ROMFSINST) -d config.opts /etc/pcmcia/config.opts

image: image.configs image.dir image.arm.zimage mkcramfs
	#mv $(ROMFSDIR)/bin/init $(ROMFSDIR)/bin/init.save
	#ln $(ROMFSDIR)/bin/recover $(ROMFSDIR)/bin/init
	./mkcramfs -z -r $(ROMFSDIR) $(CRAMFSIMG)
	#rm -f $(ROMFSDIR)/bin/init
	#mv $(ROMFSDIR)/bin/init.save $(ROMFSDIR)/bin/init
	cat $(CRAMFSIMG) $(ZIMAGE) > $(RECOVER)
	$(ROOTDIR)/tools/cksum -b -o 2 $(RECOVER) >> $(RECOVER)
	$(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2 -p -b -e 131072 -o $(JFFS2IMG) -d $(ROMFSDIR)
	( \
		dd if=$(ZIMAGE) bs=1572864 conv=sync count=1; \
		cat $(JFFS2IMG); \
	) | gzip -9 > $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
ifdef CONFIG_USER_NETFLASH_HMACMD5
	$(ROOTDIR)/user/netflash/hmacmd5 $(CONFIG_USER_NETFLASH_HMACMD5_KEY) \
		< $(IMAGE) >> $(IMAGE)
else
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
endif
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/NetGate8100.bin
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(RECOVER) /tftpboot/
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(ZIMAGE) /tftpboot/
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(CRAMFSIMG) /tftpboot/ramdisk.gz

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
