#
#	Makefile -- Build instructions for SecureEdge/SecureEdge2580
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

LINUXFILE = bzImage
ROMFSFILE = romfs.img
JFFSFILE  = jffs.img
JFFS2FILE = jffs2.img
LINUXIMG  = $(IMAGEDIR)/$(LINUXFILE)
NBIIMG    = $(IMAGEDIR)/nbi
ROMFSIMG  = $(IMAGEDIR)/$(ROMFSFILE)
JFFSIMG   = $(IMAGEDIR)/$(JFFSFILE)
JFFS2IMG  = $(IMAGEDIR)/$(JFFS2FILE)
FLASH     = $(IMAGEDIR)/flash.bin
TOOLS     = $(ROOTDIR)/tools

DIRS = 

ROMFS_DIRS = \
	bin \
	dev dev/flash \
	etc etc/config etc/default \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	usr usr/bin usr/sbin \
	var

ROMFS_DIRS += tmp var/run var/log var/tmp /var/lock var/empty

ifdef CONFIG_JFFS_FS
FSIMG = $(JFFSIMG)
endif
ifdef CONFIG_JFFS2_FS
FSIMG = $(JFFS2IMG)
endif

DEVICES = \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65  \
	mem,c,1,1      kmem,c,1,2         null,c,1,3 \
	ram0,b,1,0     ram1,b,1,1 \
	ram2,b,1,2     ram3,b,1,3 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	zero,c,1,5     random,c,1,8       urandom,c,1,9 \
	\
	ipsec,c,36,10 \
	ledman,c,126,0 \
	hifn0,c,28,0 \
	ppp,c,108,0 \
	watchdog,c,10,130 \
	\
	mtd0,c,90,0	mtdr0,c,90,1	mtdblock0,b,31,0 \
	mtd1,c,90,2	mtdr1,c,90,3	mtdblock1,b,31,1 \
	mtd2,c,90,4	mtdr2,c,90,5	mtdblock2,b,31,2 \
	mtd3,c,90,6	mtdr3,c,90,7	mtdblock3,b,31,3 \
	mtd4,c,90,8	mtdr4,c,90,9	mtdblock4,b,31,4 \
	mtd5,c,90,10	mtdr5,c,90,11	mtdblock5,b,31,5 \
	mtd6,c,90,12	mtdr6,c,90,13	mtdblock6,b,31,6

FLASH_DEVICES = \
	kernel,c,90,0 \
	rootfs,c,90,2 \
	config,c,90,4 \
	image,c,90,6 \
	bootarg,c,90,8 \
	ethmac,c,90,8 \
	boot,c,90,10 \
	all,c,90,6

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
	dirs=$(DIRS) ; for i in $$dirs; do  make -C $$i romfs || exit $? ; done
	$(ROMFSINST) ../romfs_x86 /
	$(ROMFSINST) -p 755 ../romfs_x86/etc/default/ip-up /etc/default/ip-up
	$(ROMFSINST) -p 755 ../romfs_x86/etc/default/ip-down /etc/default/ip-down
	$(ROMFSINST) -p 755 ../romfs_x86/etc/default/dhcpcd-eth0.exe \
	/etc/default/dhcpcd-eth0.exe
	$(ROMFSINST) -p 755 ../romfs_x86/etc/default/dhcpcd-eth1.exe \
	/etc/default/dhcpcd-eth1.exe

ifdef CONFIG_ROMFS_FS
	$(ROMFSINST) -s /var/tmp /tmp
endif
	$(ROMFSINST) -s /var/tmp/log /dev/log
	#echo "ttyS0::respawn:/sbin/getty 9600 -" >> $(ROMFSDIR)/etc/default/inittab
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version
	date '+%Y.%m.%d-%T' > $(ROMFSDIR)/etc/build-date

$(JFFS2IMG):
	$(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2 -o $(JFFS2IMG) -q -l -e 131072 -d $(ROMFSDIR)

$(JFFSIMG):
	$(ROOTDIR)/user/mtd-utils/build/mkfs.jffs -o $(JFFSIMG) -d $(ROMFSDIR)

$(ROMFSIMG):
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(TOOLS)/cksum -b -o 2 $(ROMFSIMG) >> $(ROMFSIMG)

.PHONY: image $(FSIMG) $(ROMFSIMG)
image: $(FSIMG) $(ROMFSIMG)
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/$(LINUXFILE) $(LINUXIMG)
	$(TOOLS)/cksum -b -o 2 $(LINUXIMG) >> $(LINUXIMG)
	(cd $(ROOTDIR); bin/make_flash)
	mknbi-linux $(LINUXIMG) --output=$(NBIIMG) --rootdir=/dev/ram0 $(ROMFSIMG)
	gzip -9 $(FLASH)
	mv $(FLASH).gz $(FLASH)
ifdef CONFIG_USER_NETFLASH_VERSION
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(FLASH)
endif
ifdef CONFIG_USER_NETFLASH_HMACMD5
	$(ROOTDIR)/user/netflash/hmacmd5 $(CONFIG_USER_NETFLASH_HMACMD5_KEY) < $(FLASH) >> $(FLASH)
else
	$(TOOLS)/cksum -b -o 2 $(FLASH) >> $(FLASH)
endif
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(FLASH) /tftpboot/.
