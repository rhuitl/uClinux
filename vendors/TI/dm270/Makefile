#
#	Makefile -- Build instructions for TI/TMS320DM270
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

LINUXFILE  = linux
ROMFSFILE  = romfs.img
INITRDFILE = initrd.img
JFFS2FILE  = jffs2.img

LINUXIMG   = $(IMAGEDIR)/$(LINUXFILE)
ROMFSIMG   = $(IMAGEDIR)/$(ROMFSFILE)
INITRDIMG  = $(IMAGEDIR)/$(INITRDFILE)
JFFS2IMG   = $(IMAGEDIR)/$(JFFS2FILE)

IMAGE      = $(IMAGEDIR)/image.bin
ELFIMAGE   = $(IMAGEDIR)/image.elf

ROMFS_DIRS = bin dev etc home lib mnt proc usr var

ifdef CONFIG_JFFS2_FS
ROMFS_DIRS += sbin var/run var/log var/tmp /var/lock var/empty
FSIMG = $(JFFS2IMG)
endif
ifdef CONFIG_BLK_DEV_INITRD
ROMFS_DIRS += sbin var/run var/log var/tmp /var/lock var/empty
FSIMG = $(INITRDIMG)
endif
ifdef CONFIG_ROMFS_FS
FSIMG = $(ROMFSIMG)
endif

DEVICES = \
	tty,c,5,0	console,c,5,1	cua0,c,5,64	cua1,c,5,65 \
	\
	mem,c,1,1	kmem,c,1,2	null,c,1,3 \
	zero,c,1,5	random,c,1,8	urandom,c,1,9  \
	\
	ptyp0,c,2,0	ptyp1,c,2,1	ptyp2,c,2,2	ptyp3,c,2,3 \
	ptyp4,c,2,4	ptyp5,c,2,5	ptyp6,c,2,6	ptyp7,c,2,7 \
	ptyp8,c,2,8	ptyp9,c,2,9	ptypa,c,2,10	ptypb,c,2,11 \
	ptypc,c,2,12	ptypd,c,2,13	ptype,c,2,14	ptypf,c,2,15 \
	\
	tty0,c,4,0	tty1,c,4,1	tty2,c,4,2	tty3,c,4,3 \
	ttyS0,c,4,64	ttyS1,c,4,65 \
	\
	ttyp0,c,3,0	ttyp1,c,3,1	ttyp2,c,3,2	ttyp3,c,3,3 \
	ttyp4,c,3,4	ttyp5,c,3,5	ttyp6,c,3,6	ttyp7,c,3,7 \
	ttyp8,c,3,8	ttyp9,c,3,9	ttypa,c,3,10	ttypb,c,3,11 \
	ttypc,c,3,12	ttypd,c,3,13	ttype,c,3,14	ttypf,c,3,15
ifdef CONFIG_FB
DEVICES += \
	fb0,c,29,0	fb1,c,29,1
endif
ifdef CONFIG_PPP
DEVICES += \
	ppp,c,108,0 \
	ptmx,c,5,2

PPPPTS = \
	0,c,136,0	1,c,136,1	2,c,136,2
endif
ifdef CONFIG_BLK_DEV_LOOP
DEVICES += \
	loop0,b,7,0	loop1,b,7,1
endif
ifdef CONFIG_BLK_DEV_BLKMEM
DEVICES += \
	rom0,b,31,0	rom1,b,31,1	rom2,b,31,2	rom3,b,31,3 \
	rom4,b,31,4	rom5,b,31,5	rom6,b,31,6	rom7,b,31,7 \
	rom8,b,31,8	rom9,b,31,9
endif
ifdef CONFIG_BLK_DEV_RAM
DEVICES += \
	ram0,b,1,0	ram1,b,1,1
endif
ifdef CONFIG_MTD_CHAR
DEVICES += \
	mtd0,c,90,0	mtdr0,c,90,1 \
	mtd1,c,90,2	mtdr1,c,90,3 \
	mtd2,c,90,4	mtdr2,c,90,5 \
	mtd3,c,90,6	mtdr3,c,90,7 \
	mtd4,c,90,8	mtdr4,c,90,9 \
	mtd5,c,90,10	mtdr5,c,90,11 \
	mtd6,c,90,12	mtdr6,c,90,13
endif
ifdef CONFIG_MTD_BLOCK
DEVICES += \
	mtdblock0,b,31,0 \
	mtdblock1,b,31,1 \
	mtdblock2,b,31,2 \
	mtdblock3,b,31,3 \
	mtdblock4,b,31,4 \
	mtdblock5,b,31,5 \
	mtdblock6,b,31,6
endif
ifdef CONFIG_VIDEO_DEV
DEVICES += \
	video0,c,81,0 \
	video1,c,81,1
endif
ifdef CONFIG_BOARD_IMPLDM270VP4
DEVICES += \
	phone0,c,100,0
endif

clean:

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
ifdef CONFIG_PPP
	[ -d $(ROMFSDIR)/dev/pts ] || mkdir -p $(ROMFSDIR)/dev/pts
	for i in $(PPPPTS); do \
		touch $(ROMFSDIR)/dev/pts/@$$i; \
	done
endif
ifdef CONFIG_FB
	$(ROMFSINST) -s /dev/fb0 /dev/fb
endif
ifdef CONFIG_VIDEO_DEV
	$(ROMFSINST) -s /dev/video0 /dev/video
endif
	$(ROMFSINST) -s /var/tmp /tmp
ifdef CONFIG_ROMFS_FS
	$(ROMFSINST) -s /bin /sbin
endif
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

modules.dep:
ifdef CONFIG_MODULES
	( \
		cd $(ROMFSDIR); \
		find ./lib/modules -type f -a ! -name modules.dep | \
		sed -e 's/$$/:/' -e 's/^\.//' \
	) > $(ROMFSDIR)/lib/modules/modules.dep
endif

$(JFFS2IMG): modules.dep
	$(ROOTDIR)/user/mtd-utils/build/mkfs.jffs2 -o $(JFFS2IMG) -q -e 65536 -d $(ROMFSDIR)

$(INITRDIMG): modules.dep
	genext2fs -b 4096 -f dev.txt -d $(ROMFSDIR) $(INITRDIMG)
	gzip -9 -f $(INITRDIMG)

$(ROMFSIMG): modules.dep
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)

.PHONY: image $(FSIMG) modules.dep
image: $(FSIMG)
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.ramvec \
			--remove-section=.eram \
			--set-section-flags=.romvec=CONTENTS,ALLOC,LOAD,READONLY,CODE \
			$(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.bin
ifdef CONFIG_RAM_ATTACHED_ROMFS
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
endif
