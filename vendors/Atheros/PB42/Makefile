#
#	Makefile -- Build instructions for Atheros/PB42 dev board
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

RAMDISK = $(IMAGEDIR)/ramdisk
KERNEL  = $(IMAGEDIR)/vmlinux

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
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/group
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	genext2fs -b 8192 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	gzip -9 -f $(RAMDISK)
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(KERNEL)
	if [ -d /tftpboot ]; then \
		cp $(KERNEL) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISK).gz /tftpboot/ 2> /dev/null; \
	fi

