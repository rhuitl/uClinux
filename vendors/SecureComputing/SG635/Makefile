#
#	Makefile -- Build instructions for CyberGuard SG635
#

CONFIG_SH_SCI_REVERSE=y

ROMFSIMG = $(IMAGEDIR)/initrd
ZIMAGE   = $(IMAGEDIR)/linuz.bin
IMAGE    = $(IMAGEDIR)/image.bin
IMAGESIZE = 15597568
FLASH    = $(IMAGEDIR)/flash.bin
BOOTLOADER = $(PRODUCTDIR)/SG635_v4.1.0p0_20090301.sgb 

SQUASH_ENDIAN = -le

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.bridge /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

image: image.configs image.dir image.linuz image.squashfs7z image.bin image.size image.tag image.copy image.flash 

#
# build up a flash.bin
#
vendor_flashbin:
	@$(DD) conv=sync if=$(ROOTDIR)/boot/boot.bin of=$(FLASH) bs=48k
	@( \
		MAC0="\000\320\317\000\000\001"; \
		MAC1="\000\320\317\000\000\002"; \
		MAC2="\000\320\317\000\000\003"; \
		MAC3="\000\320\317\000\000\004"; \
		PAD0="\000\000\000\000\000\000"; \
		MAG0="\253\272"; \
		printf "$$MAC0$$MAC1$$MAC2$$MAC3$$PAD0$$MAG0"; \
		printf "mem=64M console=ttySC1,57600\000"; \
	) | $(DD) conv=sync bs=80k >> $(FLASH)
	@echo "Bad config filesystem" | $(DD) conv=sync bs=1024k >> $(FLASH)
	@cat $(IMAGE) >> $(FLASH)
	@echo "Factory `basename $(FLASH)` created."
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
