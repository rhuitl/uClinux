#
#	Makefile -- Build instructions for INTEL/IXPD465 (XSCALE)
#

RAMDISK  = $(IMAGEDIR)/ramdisk
KERNELZ  = $(IMAGEDIR)/zImage

ROMFS_DIRS = \
	bin \
	dev \
	etc etc/config etc/default \
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
	$(ROMFSINST) /etc/group
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	-$(ROMFSINST) -e CONFIG_IXP400_LIB_2_0 \
	    -d $(ROOTDIR)/modules/ixp425/ixp400-2.0/IxNpeMicrocode.dat \
	    /etc/IxNpeMicrocode.dat
	-$(ROMFSINST) -e CONFIG_IXP400_LIB_2_1 \
	    -d $(ROOTDIR)/modules/ixp425/ixp400-2.1/IxNpeMicrocode.dat \
	    /etc/IxNpeMicrocode.dat
	-$(ROMFSINST) -e CONFIG_IXP400_LIB_2_4 \
	    -d $(ROOTDIR)/modules/ixp425/ixp400-2.4/IxNpeMicrocode.dat \
	    /etc/IxNpeMicrocode.dat
	genext2fs -b 8192 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	genext2fs -b 8192 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	gzip -9 -f $(RAMDISK)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISK).gz /tftpboot/ 2> /dev/null; \
	fi

