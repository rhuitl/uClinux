#
#	Makefile -- Build instructions for CyberGuard/SE5100
#
#	This target is built with the uClibc library
#

KERNELZ    = $(IMAGEDIR)/zImage
ROMFSIMG   = $(IMAGEDIR)/romfs.img
IMAGE      = $(IMAGEDIR)/image.bin
MBRIMG     = $(IMAGEDIR)/mbr.img
E2FSIMG    = $(IMAGEDIR)/e2fs.img
RECOVER    = $(IMAGEDIR)/recover.bin
RAMDISK    = /dev/ram0
ROMDISKMNT = $(ROOTDIR)/images/mnt1
RAMDISKMNT = $(ROOTDIR)/images/mnt2
VENDDIR    = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.


DIRS =

ROMFS_DIRS = \
	boot \
	bin \
	dev dev/flash \
	etc etc/config etc/default \
	home home/httpd home/httpd/cgi-bin \
	lib \
	mnt \
	proc \
	usr \
	var

DEVICES = \
	mem,c,1,1      kmem,c,1,2         null,c,1,3 \
	ram0,b,1,0     ram1,b,1,1         ram2,b,1,2 \
	zero,c,1,5     random,c,1,8       urandom,c,1,9 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65  \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	hda,b,3,0      hdb,b,3,64 \
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
	\
	ppp,c,108,0 \
	\
	nftla,b,93,0 \
	nftla1,b,93,1   nftla2,b,93,2 \
	nftla3,b,93,3   nftla4,b,93,4 \
	\
	watchdog,c,10,130 \
	rtc,c,10,135 \
	\
	ixDspCodeletModule,c,253,0

FLASH_DEVICES = \
	boot,c,90,0 \
	bootarg,c,90,0 \
	ethmac,c,90,0 \
	image,b,93,0 \
	recover,b,93,2 \
	config,b,93,3 \
	all,b,93,0

all:

clean:
	-rm -f lilo mkcramfs *.o

romfs:
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
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
	rm -rf $(ROMFSDIR)/sbin
	$(ROMFSINST) -s ./bin /sbin
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../romfs /
	-$(ROMFSINST) ../httpd /home/httpd
	case "$(LINUXDIR)" in \
	*2.4.*) ;; \
	*) echo "ttyS0:linux:/bin/sh" >> $(ROMFSDIR)/etc/inittab ;; \
	esac
	$(ROMFSINST) /etc/motd
	#
	# we have to fix the default passwd for uClibc/glibc
	#
	#grep -v passwd $(ROMFSDIR)/etc/default/config > .config 
	#echo "passwd eoP5S.n2WoVNo" >> .config
	#cp .config $(ROMFSDIR)/etc/default/config
	#rm -f .config
	$(ROMFSINST) /etc/lilo.conf
	$(ROMFSINST) /boot/message
	$(ROMFSINST) /boot/boot.b
	$(ROMFSINST) /boot/boot.b.le
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	-cp $(ROOTDIR)/boot/ixp425/bios.bin $(ROMFSDIR)/boot/biosplus.bin
	-cp $(ROOTDIR)/boot/ixp425/boot.bin $(ROMFSDIR)/boot/bootplus.bin
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	cp $(KERNELZ) $(ROMFSDIR)/boot/vmlinuz
	./mkcramfs -z -r $(ROMFSDIR) $(ROMFSIMG)
	cat $(ROMFSIMG) $(KERNELZ) > $(RECOVER)
	#
	# and put it back
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
# Real filesystem building from here on in
#

LILO_CFLAGS = -I$(ROOTDIR)/user/lilo -DLCF_IGNORECASE -DHAS_BOOT_H -DLCF_M386 -DLCF_READONLY -DLCF_VARSETUP -DNOSIZELIMIT=1
#LILO_CFLAGS = -I$(ROOTDIR)/user/lilo -DLCF_IGNORECASE -DHAS_BOOT_H -DLCF_M386 -DLCF_READONLY -DLCF_VARSETUP

LILOSOURCE = lilo.c map.c geometry.c boot.c device.c common.c bsect.c cfg.c \
	temp.c partition.c identify.c probe.c shs2.c

lilo:
	# Note: A binary is now checked into CVS to make this less dependent
	# on the host system
	#gcc $(LILO_CFLAGS) -o $@ $(patsubst %.c,$(ROOTDIR)/user/lilo/%.c,$(LILOSOURCE))

.PHONY: extimage
extimage: lilo
	dd if=/dev/zero of=$(MBRIMG) bs=512 count=1
	printf "1,44479,L,*\n,16384,3c,-\n,,61,-\n" | /sbin/sfdisk  -uS -C 966 -H 16 -S 4 $(MBRIMG)
	dd if=/dev/zero of=$(E2FSIMG) bs=512 count=44478
	/sbin/mke2fs -F -m0 -v $(E2FSIMG)
	/sbin/tune2fs -i 0 -j $(E2FSIMG)
	[ -d $(ROMDISKMNT) ] || mkdir -p $(ROMDISKMNT)
	[ -d $(RAMDISKMNT) ] || mkdir -p $(RAMDISKMNT)
	( \
		trap "cd $(ROOTDIR); umount $(RAMDISKMNT); umount $(ROMDISKMNT); sleep 1; rmdir $(RAMDISKMNT) $(ROMDISKMNT)" 0; \
		mount -t cramfs -o loop $(ROMFSIMG) $(ROMDISKMNT); \
		mount -t ext2 -o loop $(E2FSIMG) $(RAMDISKMNT); \
		DEV=`mount|grep $(E2FSIMG)|sed 's?.*loop=/dev/loop\([0-9]\).*$$?\1?'`;\
		echo "#Device Bios    Sectors Heads   Cyls    Start" > disktab; \
		echo "0x70$$DEV	0x80	2	16	999	1" >> disktab ; \
		(cd $(ROMDISKMNT); tar cf - .) | (cd $(RAMDISKMNT); tar xf -); \
		chmod -R go-w $(RAMDISKMNT) ; \
		chgrp -hR root $(RAMDISKMNT); \
		chown -hR root $(RAMDISKMNT); \
		cd $(IMAGEDIR); \
		chmod +x $(VENDDIR)/lilo; \
		$(VENDDIR)/lilo -C $(VENDDIR)/build.lilo.conf -f $(VENDDIR)/disktab; \
		rm -f disktab; \
		cd $(ROOTDIR); \
	)
	cat $(MBRIMG) $(E2FSIMG) | gzip -9 > $(IMAGE)
ifdef CONFIG_USER_NETFLASH_HMACMD5
	$(ROOTDIR)/user/netflash/hmacmd5 $(CONFIG_USER_NETFLASH_HMACMD5_KEY) \
		< $(IMAGE) >> $(IMAGE)
else
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
endif
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/flash.bin
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(RECOVER) /tftpboot/

