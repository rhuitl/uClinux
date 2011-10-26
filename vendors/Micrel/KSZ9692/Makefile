#
#	Makefile -- Build instructions for Kendin/Micrel/KSZ9692
#

RAMDISK = $(IMAGEDIR)/ramdisk
KERNELZ = $(IMAGEDIR)/zImage
UIMAGE	= $(IMAGEDIR)/uImage

ROMFS_DIRS = \
	bin \
	dev \
	etc etc/config \
	home home/httpd \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	tmp \
	usr usr/bin usr/sbin \
	var var/lock var/log var/run var/tmp var/empty


clean:

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	ln -sf bin/sh $(ROMFSDIR)/linuxrc
	#$(ROMFSINST) /etc/emc
	#$(ROMFSINST) /linuxrc
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genext2fs -b 5120 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	gzip -9 -f $(RAMDISK)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	mkimage -A arm -O linux -T multi -C none -a 0x00008000 -e 0x00008000 -n LINUX -d $(KERNELZ):$(RAMDISK).gz $(UIMAGE)
	if [ -d /tftpboot ]; then \
		cp $(UIMAGE) /tftpboot/ 2> /dev/null; \
	fi

