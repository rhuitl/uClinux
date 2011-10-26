#
#	Makefile -- Build instructions for SecureComputing/SE5000
#

KERNELZ  = $(IMAGEDIR)/bzImage
IMAGE    = $(IMAGEDIR)/image.bin
INITRD   = $(IMAGEDIR)/initrd
INITRDZ  = $(IMAGEDIR)/initrd.gz
MBRIMG   = $(IMAGEDIR)/mbr.img
E2FSIMG  = $(IMAGEDIR)/e2fs.img
ROMFSIMG = $(IMAGEDIR)/romfs.img

RAMDISK    = /dev/ram0
ROMDISKMNT = $(ROOTDIR)/images/mnt1
RAMDISKMNT = $(ROOTDIR)/images/mnt2
VENDDIR    = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.

ROMFS_DIRS = \
	bin boot \
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
	boot,c,90,2 \
	bootarg,c,90,0 \
	ethmac,c,90,0 \
	image,b,3,0 \
	config,b,3,2 \
	all,b,3,0

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
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/filesystems
	$(ROMFSINST) /etc/lilo.conf
	$(ROMFSINST) /boot/message
	$(ROMFSINST) $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/bzImage /boot/vmlinuz
	echo "$(VERSIONSTR) -- $(BUILD_START_STRING)" > $(ROMFSDIR)/etc/version

.PHONY: mksquashfs7z
mksquashfs7z:
	make -C $(ROOTDIR)/user/squashfs/squashfs-tools mksquashfs7z
	ln -fs $(ROOTDIR)/user/squashfs/squashfs-tools/mksquashfs7z .

.PHONY: image
image: mksquashfs7z
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -f $(INITRD)
	mksquashfs7z=`pwd`/mksquashfs7z; cd $(ROMFSDIR); \
	    $$mksquashfs7z . $(INITRD) -all-root -noappend $(SQUASH_ENDIAN)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/bzImage $(KERNELZ)
	gzip -9 -f $(INITRD)
	#
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	#
	@if [ -x /usr/local/bin/root ]; then \
		/usr/local/bin/root $(MAKE) extimage ; \
	else \
		@echo '********************************************************' > /dev/tty ; \
		@echo '********************************************************' > /dev/tty ; \
		@echo '**                                                    **' > /dev/tty ; \
		@echo '**                                                    **' > /dev/tty ; \
		@echo '** Time to make the real filesystem image.            **' > /dev/tty ; \
		@echo '** For this you need to be "root". You will also need **' > /dev/tty ; \
		@echo '** a kernel with the loopback device enabled and ext2 **' > /dev/tty ; \
		@echo '** filesystem support.  Enter the root password below **' > /dev/tty ; \
		@echo '** if asked,  or ^C to abort.                         **' > /dev/tty ; \
		@echo '**                                                    **' > /dev/tty ; \
		@echo '**                                                    **' > /dev/tty ; \
		@echo '********************************************************' > /dev/tty ; \
		@echo '********************************************************' > /dev/tty ; \
		@echo > /dev/tty ; \
		su root -c "$(MAKE) extimage" < /dev/tty > /dev/tty 2>&1 ; \
	fi
	#
	if [ -d /tftpboot -a -z "$(NO_BUILD_INTO_TFTPBOOT)" ]; then \
                cp $(IMAGE) /tftpboot/ 2> /dev/null; \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(INITRDZ) /tftpboot/ 2> /dev/null; \
        fi


#
# Real filesystem building from here on in
#

LILO_CFLAGS = -I$(ROOTDIR)/user/lilo -DLCF_IGNORECASE -DHAS_BOOT_H -DLCF_M386 -DLCF_READONLY -DLCF_VARSETUP

LILOSOURCE = lilo.c map.c geometry.c boot.c device.c common.c bsect.c cfg.c \
	temp.c partition.c identify.c probe.c shs2.c

.PHONY: lilo
lilo:
	#gcc $(LILO_CFLAGS) -o $@ $(patsubst %.c,$(ROOTDIR)/user/lilo/%.c,$(LILOSOURCE))

.PHONY: extimage
extimage: lilo
	dd if=/dev/zero of=$(MBRIMG) bs=512 count=1
	printf "1,121599,L,*\n,,61,-\n" | /sbin/sfdisk  -uS -C 977 -H 4 -S 32 $(MBRIMG)
	dd if=/dev/zero of=$(E2FSIMG) bs=1024 count=57344
	/sbin/mke2fs -F -m0 -v $(E2FSIMG)
	/sbin/tune2fs -i 0 -j $(E2FSIMG)
	[ -d $(ROMDISKMNT) ] || mkdir -p $(ROMDISKMNT)
	[ -d $(RAMDISKMNT) ] || mkdir -p $(RAMDISKMNT)
	chmod 777 $(VENDDIR)/lilo
	( \
		trap "cd $(ROOTDIR); umount $(RAMDISKMNT); umount $(ROMDISKMNT); sleep 1; rmdir $(RAMDISKMNT) $(ROMDISKMNT)" 0; \
		mount -t romfs -o loop $(ROMFSIMG) $(ROMDISKMNT); \
		mount -t ext3 -o loop $(E2FSIMG) $(RAMDISKMNT); \
		DEV=`mount|grep $(E2FSIMG)|sed 's?.*loop=/dev/loop\([0-9]\).*$$?\1?'`;\
		echo "#Device Bios    Sectors Heads   Cyls    Start" > disktab; \
		echo "0x70$$DEV	0x80	32	4	977	1" >> disktab ; \
		cp disktab /tmp/ ; \
		cp -r $(ROMDISKMNT)/* $(RAMDISKMNT); \
		chmod -R go-w $(RAMDISKMNT); \
		chgrp -hR root $(RAMDISKMNT); \
		chown -hR root $(RAMDISKMNT); \
		cd $(IMAGEDIR); \
		$(VENDDIR)/lilo -C $(VENDDIR)/build.lilo.conf -f $(VENDDIR)/disktab ; \
		rm -f disktab; \
		cd $(ROOTDIR); \
	)
	cat $(MBRIMG) $(E2FSIMG) | gzip -9 > $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)

#(cd $(ROMDISKMNT); tar cf - .) | (cd $(RAMDISKMNT); tar xf -); \

include $(ROOTDIR)/vendors/config/config.dev

