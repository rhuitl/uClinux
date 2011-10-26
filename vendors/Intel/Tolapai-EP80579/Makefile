#
#	Makefile -- Build instructions for VIA-NAB-7500
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

LINUXIMG = $(IMAGEDIR)/Intel-Tolapai-EP80579-vmlinuz
ROMFSIMG = $(IMAGEDIR)/initrd

VENDOR_ROMFS_DIR := ../../SecureComputing

FLASH_DEVICES =

SQUASH_ENDIAN = -le

ROMFS_DIRS = $(DEFAULT_ROMFS_DIRS) etc/config EP805XX lib/firmware

DEVICES += $(DEVICE_PTY_64)

all:

clean: image.clean
	-test '$(ICP_ROOT)' && $(MAKE) -C $(ICP_ROOT) clean

image.initramfs:
	cp $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/bzImage $(LINUXIMG)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(LINUXIMG) /tftpboot/.

romfs.post::
	$(MAKE) -C $(ICP_ROOT)
	$(ROMFSINST) -s /bin/init /init
	$(ROMFSINST) -s /EP805XX/icp_asd.conf /etc/icp_asd.conf
	$(ROMFSINST) -s /EP805XX/mmp_firmware.bin /lib/firmware/mmp_firmware.bin
	$(ROMFSINST) -s /EP805XX/uof_firmware.bin /lib/firmware/uof_firmware.bin
	cp $(ICP_ROOT)/binaries/* $(ROMFSDIR)/EP805XX/.
	( \
		cd $(ROOTDIR)/romfs; \
		grep -v setmac < etc/rc > etc/rc.new; \
		mv etc/rc.new etc/rc; \
		find . | cpio --quiet -o -H newc > $(CONFIG_INITRAMFS_SOURCE); \
	)

romfs: romfs_dev_sudo romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/network.init.std /etc/network.init
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/firewall.init.std /etc/firewall.init

image: image.configs image.dir image.cramfs image.initramfs

include $(ROOTDIR)/vendors/config/config.dev
include $(ROOTDIR)/vendors/SecureComputing/vendor.mak


#############################################################################
