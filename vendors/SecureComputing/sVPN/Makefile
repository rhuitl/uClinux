#
#	Makefile -- Build instructions for CyberGuard/sVPN 20Mhz unit
#

IMAGE    = $(IMAGEDIR)/image.bin
FLASH    = $(IMAGEDIR)/flash.bin
RAMDISK  = $(IMAGEDIR)/ramdisk
KERNELZ  = $(IMAGEDIR)/zImage
SQUASH_ENDIAN = -be

ROMFS_DIRS = \
    bin \
    dev dev/flash dev/pts \
    etc etc/config \
    home home/httpd home/httpd/cgi-bin \
    lib lib/modules \
    proc \
    sbin \
    usr \
    var

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
    boot,c,90,0 \
    ethmac,c,90,0 \
    bootarg,c,90,0 \
    config,c,90,2 \
    image,c,90,4 \
    all,c,90,6

all:

clean:
	-rm -f mksquashfs7z

romfs: romfs_dev
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) network.init.ivpn /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -p 755 eth1_2_wifi /etc/default/eth1_2_wifi
	$(ROMFSINST) -p 755 wifi_2_eth1 /etc/default/wifi_2_eth1
	#
	#
	$(ROMFSINST) /etc/rc
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

.PHONY: mksquashfs7z
mksquashfs7z:
	make -C $(ROOTDIR)/user/squashfs/squashfs-tools mksquashfs7z
	ln -fs $(ROOTDIR)/user/squashfs/squashfs-tools/mksquashfs7z .

image: mksquashfs7z
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400/ixp400_*.o
	rm -rf $(ROMFSDIR)/man[1-9]
	rm -f $(RAMDISK); mksquashfs7z=`pwd`/mksquashfs7z; cd $(ROMFSDIR); \
	    $$mksquashfs7z . $(RAMDISK) -all-root -noappend $(SQUASH_ENDIAN)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cat $(RAMDISK) $(KERNELZ) > $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	#
	# build up a flash.bin
	#
	if [ -f $(ROOTDIR)/boot/boot.bin ] ; then \
		dd conv=sync if=$(ROOTDIR)/boot/boot.bin bs=256k of=$(FLASH) ; \
		cat $(IMAGE) >> $(FLASH) ; \
	fi
	if [ -d /tftpboot -a -z "$(NO_BUILD_INTO_TFTPBOOT)" ]; then \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi

include $(ROOTDIR)/vendors/config/config.dev
