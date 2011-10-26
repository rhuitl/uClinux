#
#	Makefile -- Build instructions for Feith SCALES
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ   = $(IMAGEDIR)/imagez.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

DIRS = ../cgi/SCALES

ROMFS_DIRS = bin dev dev/flash etc etc/config etc/default home lib mnt proc \
             usr var home/httpd home/httpd/cgi-bin home/httpd/img dev/usb

USB_DEVICES = dabusb0,180,240

DEVICES = \
	tty,c,5,0	console,c,5,1	cua0,c,5,64	cua1,c,5,65 \
	mem,c,1,1	kmem,c,1,2	null,c,1,3	zero,c,1,5 \
	\
	random,c,1,8	urandom,c,1,9 \
	\
	ram0,b,1,0	ram1,b,1,1	ram2,b,1,2	ram3,b,1,3 \
	\
	ptyp0,c,2,0	ptyp1,c,2,1	ptyp2,c,2,2	ptyp3,c,2,3 \
	ptyp4,c,2,4	ptyp5,c,2,5	ptyp6,c,2,6	ptyp7,c,2,7 \
	ptyp8,c,2,8	ptyp9,c,2,9	ptypa,c,2,10	ptypb,c,2,11 \
	ptypc,c,2,12	ptypd,c,2,13	ptype,c,2,14	ptypf,c,2,15 \
	\
	ttyp0,c,3,0	ttyp1,c,3,1	ttyp2,c,3,2	ttyp3,c,3,3 \
	ttyp4,c,3,4	ttyp5,c,3,5	ttyp6,c,3,6	ttyp7,c,3,7 \
	ttyp8,c,3,8	ttyp9,c,3,9	ttypa,c,3,10	ttypb,c,3,11 \
	ttypc,c,3,12	ttypd,c,3,13	ttype,c,3,14	ttypf,c,3,15 \
	tty0,c,4,0	tty1,c,4,1	tty2,c,4,2	tty3,c,4,3 \
	ttyS0,c,4,64	ttyS1,c,4,65 \
	\
	qspi0,c,126,0	qspi1,c,126,1	qspi2,c,126,2	qspi3,c,126,3 \
	qspi4,c,126,4	qspi5,c,126,5	qspi6,c,126,6	qspi7,c,126,7 \
	qspi8,c,126,8	qspi9,c,126,9	qspi10,c,126,10	qspi11,c,126,11	\
	qspi12,c,126,12	qspi13,c,126,13	qspi14,c,126,14 \
	\
	ipsec,c,36,10 \
	ppp,c,108,0 \
	lcd20,c,120,0

ifdef CONFIG_BLK_DEV_BLKMEM

	DEVICES += \
		rom0,b,31,0    rom1,b,31,1        rom2,b,31,2      rom3,b,31,3 \
		rom4,b,31,4    rom5,b,31,5        rom6,b,31,6      rom7,b,31,7 \
		rom8,b,31,8    rom9,b,31,9        rom10,b,31,10

	FLASH_DEVICES = \
		boot,b,31,1 \
		bootarg,b,31,2 \
		ethmac,b,31,3 \
		image,b,31,4 \
		config,b,31,5 \
		all,b,31,6

else
	DEVICES += \
		mtd0,c,90,0	mtdr0,c,90,1	mtdblock0,b,31,0 \
		mtd1,c,90,2	mtdr1,c,90,3	mtdblock1,b,31,1 \
		mtd2,c,90,4	mtdr2,c,90,5	mtdblock2,b,31,2 \
		mtd3,c,90,6	mtdr3,c,90,7	mtdblock3,b,31,3 \
		mtd4,c,90,8	mtdr4,c,90,9	mtdblock4,b,31,4 \
		mtd5,c,90,10	mtdr5,c,90,11	mtdblock5,b,31,5 \
		mtd6,c,90,12	mtdr6,c,90,13	mtdblock6,b,31,6 \
		mtd7,c,90,14	mtdr7,c,90,15	mtdblock7,b,31,7 \

	FLASH_DEVICES = \
		boot,c,90,0 \
		bootarg,c,90,2 \
		ethmac,c,90,4 \
		image,c,90,6 \
		config,c,90,8 \
		all,c,90,10 \
		spare,c,90,12 \
		userconfig,c,90,14
endif


all:
	for i in $(DIRS) ; do  make -C $$i || exit $? ; done

clean:
	-for i in $(DIRS); do [ ! -d $$i ] || make -C $$i clean; done

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

	for i in $(USB_DEVICES); do \
		touch $(ROMFSDIR)/dev/usb/@$$i; \
	done

	for i in $(DIRS); do make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../romfs/SCALES /
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version


image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
			$(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	cp $(IMAGE) /tftpboot
	gzip -c -9 $(IMAGE) > $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	cp $(IMAGEZ) /tftpboot
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null

vendor_flash:
	$(ROOTDIR)/bin/make_flash
	$(CROSS)objcopy --input-target=binary --output-target=srec --adjust-vma 0xf0000000 \
	$(IMAGEDIR)/flash.bin $(IMAGEDIR)/flash.s19

