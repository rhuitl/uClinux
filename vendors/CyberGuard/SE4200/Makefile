#
#	Makefile -- Build instructions for CyberGuard SE4200
#

KERNELZ  = $(IMAGEDIR)/zImage
RAMDISK  = $(IMAGEDIR)/ramdisk
RAMDISKZ = $(IMAGEDIR)/ramdisk.gz
IMAGE    = $(IMAGEDIR)/image.bin

ROMFS_DIRS = \
	bin \
	dev dev/flash \
	etc etc/config \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	proc \
	sbin \
	usr usr/bin usr/sbin \
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
	-rm -f mkcramfs

romfs: romfs_dev
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	#
	$(ROMFSINST) /etc/rc
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)
	cp $(RAMDISK) $(RAMDISKZ)

	cp $(RAMDISKZ) $(IMAGE)
	cat $(KERNELZ) >> $(IMAGE)
	
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)

	if [ -d /tftpboot -a -z "$(NO_BUILD_INTO_TFTPBOOT)" ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISKZ) /tftpboot/ 2> /dev/null; \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi

include $(ROOTDIR)/vendors/config/config.dev

