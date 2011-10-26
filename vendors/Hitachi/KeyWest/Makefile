#
#	Makefile -- Build instructions for Hitachi/KeyWest
#

ROMFSIMG = $(IMAGEDIR)/initrd
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ   = $(IMAGEDIR)/imagez.bin
IMAGES   = $(IMAGEDIR)/sh.srec

ROMFS_DIRS = bin dev/flash etc etc/config home lib mnt proc usr var \
             home/httpd home/httpd/cgi-bin

DEVICES = \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65  \
	mem,c,1,1      kmem,c,1,2         null,c,1,3 \
	ram0,b,1,0     ram1,b,1,1         ram2,b,1,2 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	rom0,b,31,0    rom1,b,31,1        rom2,b,31,2      rom3,b,31,3 \
	rom4,b,31,4    rom5,b,31,5        rom6,b,31,6      rom7,b,31,7 \
	rom8,b,31,8    rom9,b,31,9 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	hda,b,3,0      hdb,b,3,64 \
	\
	zero,c,1,5     random,c,1,8       urandom,c,1,9 \
	\
	mtd0,c,90,0    mtdr0,c,90,1      mtdblock0,b,31,0	\
	mtd1,c,90,2    mtdr1,c,90,3      mtdblock1,b,31,1	\
	mtd2,c,90,4    mtdr2,c,90,5      mtdblock2,b,31,2	\
	mtd3,c,90,6    mtdr3,c,90,7      mtdblock3,b,31,3	\
	mtd4,c,90,8    mtdr4,c,90,9      mtdblock4,b,31,4	\
	mtd5,c,90,10   mtdr5,c,90,11     mtdblock5,b,31,5	\
	mtd6,c,90,12   mtdr6,c,90,13     mtdblock6,b,31,6	\
	\
	modem,c,24,64 \
	cuam,c,25,64 \
	ipsec,c,36,10 \
	ledman,c,126,0 \
	xymem,c,127,0 xmem,c,127,1 ymem,c,127,2 \
	ttySC0,c,204,8 ttySC1,c,204,9 ttySC2,c,204,10\
	hifn0,c,28,0 \
	\
	mixer,c,14,0 mixer1,c,16,0 \
	sequencer,c,14,1 \
	midi00,c,14,2 midi01,c,14,18 midi02,c,14,34 midi03,c,14,50 \
	dsp,c,14,3 dsp1,c,14,19 \
	audio,c,14,4 audio1,c,14,10 \
	sndstat,c,14,6 \
	\
	ppp,c,108,0

FLASH_DEVICES = \
	boot,c,90,0 \
	bootarg,c,90,2 \
	config,c,90,4 \
	image,c,90,8 \
	all,c,90,10

all:

clean:

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
	$(ROMFSINST) -s ./bin /sbin
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	case "$(LINUXDIR)" in \
	*2.4.*) ;; \
	*) echo "ttyS0:linux:/bin/sh" >> $(ROMFSDIR)/etc/inittab ;; \
	esac
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	-$(CROSS)strip $(ROMFSDIR)/bin/*
	-$(CROSS)strip $(ROMFSDIR)/sbin/*
	-$(CROSS)strip $(ROMFSDIR)/home/httpd/cgi-bin/*
	rm -rf $(ROMFSDIR)/man[1-9]
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/vmlinux \
			$(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot
	gzip -c -9 $(IMAGE) > $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGEZ) /tftpboot
	ADDR=`$(CROSS)nm $(ROOTDIR)/$(LINUXDIR)/vmlinux | grep " __bss_start$$" | \
		cut -d' ' -f1 | xargs printf "0x%s\n"`;\
		echo "ROMFS@$$ADDR" ; \
        $(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
          --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
          --set-section-flags=.romfs=alloc,load,data   \
		  -O srec \
          $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGES)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGES) /tftpboot/.
