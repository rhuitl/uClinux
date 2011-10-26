#
#	Makefile -- Build instructions for CyberGuard SE4700
#

IMAGE    = $(IMAGEDIR)/image.bin
FLASH    = $(IMAGEDIR)/flash.bin
RAMDISK  = $(IMAGEDIR)/ramdisk
KERNELZ  = $(IMAGEDIR)/zImage

ROMFS_DIRS = \
	bin \
	dev dev/flash \
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
	rm -f mkcramfs

romfs: romfs_dev
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	#
	# we have to fix the default passwd for uClibc/glibc
	#
	if [ -f $(ROMFSDIR)/etc/default/config ] ; then \
		grep -v passwd $(ROMFSDIR)/etc/default/config > .config ; \
	fi
	echo "passwd eoP5S.n2WoVNo" >> .config
	cp .config $(ROMFSDIR)/etc/default/config
	rm -f .config
	#
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/default/start
	$(ROMFSINST) /etc/default/config
	$(ROMFSINST) /etc/default/inittab
	$(ROMFSINST) /etc/default/routeconfig
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400/ixp400_*.o
	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)

	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cat $(RAMDISK) $(KERNELZ) > $(IMAGE)

	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)

	if [ -d $(ROOTDIR)/boot ]; then \
		dd conv=sync if=$(ROOTDIR)/boot/boot.bin bs=256k of=$(FLASH); \
		cat $(IMAGE) >> $(FLASH); \
	fi

	if [ -d /tftpboot -a -z "$(NO_BUILD_INTO_TFTPBOOT)" ]; then \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi

include $(ROOTDIR)/vendors/config/config.dev

