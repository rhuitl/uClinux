#
#	Makefile -- Build instructions for SnapGear/SE5000 board
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

LINUXFILE  = bzImage
LINUXIMG   = $(IMAGEDIR)/$(LINUXFILE)
IMAGE      = $(IMAGEDIR)/image.bin
ROMFSIMG   = $(IMAGEDIR)/romfs.img
MBRIMG     = $(IMAGEDIR)/mbr.img
E2FSIMG    = $(IMAGEDIR)/e2fs.img
RAMDISK    = /dev/ram0
ROMDISKMNT = $(ROOTDIR)/images/mnt1
RAMDISKMNT = $(ROOTDIR)/images/mnt2
VENDDIR    = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.

DIRS = 

ROMFS_DIRS = \
	bin \
	boot \
	dev dev/flash \
	etc etc/default etc/config \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	usr usr/bin usr/sbin \
	var

DEVICES = \
	mem,c,1,1      kmem,c,1,2         null,c,1,3 \
	zero,c,1,5     random,c,1,8       urandom,c,1,9 \
	ram0,b,1,0     ram1,b,1,1         ram2,b,1,2       ram3,b,1,3 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	tty,c,5,0      console,c,5,1 \
	ttyS0,c,4,64   ttyS1,c,4,65       cua0,c,5,64      cua1,c,5,65 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	hda,b,3,0 \
	hda1,b,3,1     hda2,b,3,2        hda3,b,3,3        hda4,b,3,4 \
	hdb,b,3,64 \
	hdb1,b,3,65    hdb2,b,3,66       hdb3,b,3,67       hdb4,b,3,68 \
	\
	mtd0,c,90,0    mtdr0,c,90,1      mtdblock0,b,31,0	\
	mtd1,c,90,2    mtdr1,c,90,3      mtdblock1,b,31,1	\
	mtd2,c,90,4    mtdr2,c,90,5      mtdblock2,b,31,2	\
	mtd3,c,90,6    mtdr3,c,90,7      mtdblock3,b,31,3	\
	mtd4,c,90,8    mtdr4,c,90,9      mtdblock4,b,31,4	\
	mtd5,c,90,10   mtdr5,c,90,11     mtdblock5,b,31,5	\
	mtd6,c,90,12   mtdr6,c,90,13     mtdblock6,b,31,6	\
	mtd7,c,90,14   mtdr7,c,90,15     mtdblock7,b,31,7	\
	mtd8,c,90,16   mtdr8,c,90,17     mtdblock8,b,31,8	\
	\
	ipsec,c,36,10 \
	ledman,c,126,0 \
	ppp,c,108,0 \
	cryptic,c,44,0 \
	hifn0,c,28,0 \
	nvram,c,10,144

FLASH_DEVICES = \
	boot,c,90,0 \
	bootarg,c,90,0 \
	ethmac,c,90,0 \
	image,b,3,0 \
	config,b,3,2 \
	all,b,3,0


all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	# these permissions are needed for openpty and family to work
	# on non-ptmx ptys
	chmod 620 $(ROMFSDIR)/dev/@[pt]ty[pqrsPQRS][0-9a-f],*
	for i in $(FLASH_DEVICES); do \
		touch $(ROMFSDIR)/dev/flash/@$$i; \
	done
	$(ROMFSINST) ../../SecureEdge/romfs /
	$(ROMFSINST) ../../SecureEdge/romfs_x86/etc/protocols /etc/protocols
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/lilo.conf
	$(ROMFSINST) /boot/message
	$(ROMFSINST) ../../../$(LINUXDIR)/arch/i386/boot/$(LINUXFILE) /boot/vmlinuz
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	#echo "ttyS0::respawn:/sbin/getty 9600 -" >> $(ROMFSDIR)/etc/inittab
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version
	date '+%Y.%m.%d-%T' > $(ROMFSDIR)/etc/build-date

.PHONY: image
image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)

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
# Real filesystem building from here on in
#

LILO_CFLAGS = -I$(ROOTDIR)/user/lilo -DLCF_IGNORECASE -DHAS_BOOT_H -DLCF_M386 -DLCF_READONLY -DLCF_VARSETUP -DLCF_SOLO_CHAIN -DLILO=0xbb920890

LILOSOURCE = lilo.c map.c geometry.c boot.c device.c common.c bsect.c cfg.c \
	temp.c partition.c identify.c probe.c shs2.c raid.c edit.c

.PHONY: lilo
lilo:
	gcc $(LILO_CFLAGS) -o $@ $(patsubst %.c,$(ROOTDIR)/user/lilo/%.c,$(LILOSOURCE))

.PHONY: extimage
extimage: lilo
	dd if=/dev/zero of=$(MBRIMG) bs=512 count=1
	printf "1,121599,L,*\n,,61,-\n" | /sbin/sfdisk  -uS -C 977 -H 4 -S 32 $(MBRIMG)
	dd if=/dev/zero of=$(E2FSIMG) bs=512 count=44478
	/sbin/mke2fs -F -m0 -v $(E2FSIMG)
	/sbin/tune2fs -i 0 -j $(E2FSIMG)
	[ -d $(ROMDISKMNT) ] || mkdir -p $(ROMDISKMNT)
	[ -d $(RAMDISKMNT) ] || mkdir -p $(RAMDISKMNT)
	( \
		trap "cd $(ROOTDIR); umount $(RAMDISKMNT); umount $(ROMDISKMNT); sleep 1; rmdir $(RAMDISKMNT) $(ROMDISKMNT)" 0; \
		mount -t romfs -o loop $(ROMFSIMG) $(ROMDISKMNT); \
		mount -t ext3 -o loop $(E2FSIMG) $(RAMDISKMNT); \
		DEV=`mount|grep $(E2FSIMG)|sed 's?.*loop=/dev/loop\([0-9]\).*$$?\1?'`;\
		echo "#Device Bios    Sectors Heads   Cyls    Start" > disktab; \
		echo "0x70$$DEV	0x80	32	4	977	1" >> disktab ; \
		cp disktab /tmp/ ; \
		(cd $(ROMDISKMNT); tar cf - .) | (cd $(RAMDISKMNT); tar xf -); \
		chmod -R go-w $(RAMDISKMNT) ; \
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
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/.
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/flash.bin

