#
#	Makefile -- Build instructions for CyberGuard SG530
#

CONFIG_SH_SCI_REVERSE=y

ROMFSIMG = $(IMAGEDIR)/initrd
ZIMAGE   = $(IMAGEDIR)/linuz.bin
IMAGE    = $(IMAGEDIR)/image.bin
FLASH    = $(IMAGEDIR)/flash.bin

SQUASH_ENDIAN = -le

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS)

DEVICES += $(DEVICE_PTY_64)

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init

image: image.configs image.dir image.linuz image.squashfs7z image.bin image.tag image.sh.mot image.copy image.flash 

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
		if [ "$(CONFIG_SH_CONSOLE_TTYSC0)" = "y" ]; then \
			printf "mem=16M console=ttySC0,57600\000"; \
		else \
			printf "mem=16M console=ttySC1,57600\000"; \
		fi; \
	) | $(DD) conv=sync bs=80k >> $(FLASH)
	@echo "Bad config filesystem" | $(DD) conv=sync bs=256k >> $(FLASH)
	@cat $(IMAGE) >> $(FLASH)
	@echo "Factory `basename $(FLASH)` created."
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak

