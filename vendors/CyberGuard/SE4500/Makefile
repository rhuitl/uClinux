#
#	Makefile -- Build instructions for CyberGuard SE4500
#

IMAGE    = $(IMAGEDIR)/image.bin
ROMFSIMG = $(IMAGEDIR)/romfs.img
KERNELZ  = $(IMAGEDIR)/zImage

ROMFS_DIRS = \
	bin \
	dev dev/flash dev/pts \
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
	config,c,90,2 \
	image,c,90,4 \
	kernel,c,90,6 \
	rootfs,c,90,8


all:

clean:
	-rm -f mkcramfs

romfs: romfs_dev
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/default/start
	$(ROMFSINST) /etc/default/inittab
	$(ROMFSINST) /etc/default/config
	$(ROMFSINST) /etc/default/routeconfig
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
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400/ixp400_*.o
	./mkcramfs -z -r $(ROMFSDIR) $(ROMFSIMG)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cp $(KERNELZ) $(IMAGE)
	SIZE=`wc -c $(KERNELZ) | awk '{ print $$1 }'` ; \
	PAD=`expr 1048576 - $$SIZE` ; \
	dd if=/dev/zero count=1 bs=$$PAD 2> /dev/null | tr \\000 \\377 >> $(IMAGE)
	cat $(ROMFSIMG) >> $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot

include $(ROOTDIR)/vendors/config/config.dev

