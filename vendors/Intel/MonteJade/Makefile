#
#	Makefile -- Build instructions for INTEL/MonteJade (XSCALE)
#

RAMDISK  = $(IMAGEDIR)/ramdisk
KERNELZ  = $(IMAGEDIR)/zImage
IMAGE    = $(IMAGEDIR)/image.bin

ROMFS_DIRS = \
	bin \
	dev \
	etc \
	home home/httpd \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	usr usr/bin usr/sbin \
	var 


DEVICES += $(DEVICE_PTY_32)

clean:

romfs: romfs_dev
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(FLASH_DEVICES); do \
		touch $(ROMFSDIR)/dev/flash/@$$i; \
	done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/config /etc/config
	$(ROMFSINST) -s /var/tmp/log /dev/log
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

romfs.post::
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/group
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
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
	#rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400/ixp400_*.o
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400*/ixp400_[abe-z]*.o
	#rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400*/ixp400_codelets_[abce-tv-z]*.o
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400*/ixp400_*dma*.o
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400*/ixp400_*codec*.o

	#genext2fs -b 8192 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)
	gzip -9 -f $(RAMDISK)

	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cp $(KERNELZ) $(IMAGE)
	SIZE=`wc -c $(KERNELZ) | awk '{ print $$1 }'` ; \
	PAD=`expr 1048576 - $$SIZE` ; \
	dd if=/dev/zero count=1 bs=$$PAD 2> /dev/null | tr \\000 \\377 >> $(IMAGE)
	cat $(RAMDISK).gz >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISK).gz /tftpboot/ 2> /dev/null; \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi

include $(ROOTDIR)/vendors/config/config.dev
