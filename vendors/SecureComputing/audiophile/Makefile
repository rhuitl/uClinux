#
#	Makefile -- Build instructions for SecureComputing/audiophile
#

KERNELZ  = $(IMAGEDIR)/zImage
RAMDISK  = $(IMAGEDIR)/ramdisk
RAMDISKZ = $(IMAGEDIR)/ramdisk.gz
IMAGE    = $(IMAGEDIR)/image.bin

ROMFS_SOURCE_BASE := romfs

ROMFS_DIRS = \
	bin  \
	dev dev/flash \
	etc etc/config etc/default \
	home \
	lib \
	mnt \
	proc \
	usr \
	var

DEVICES = \
	sda,b,8,0 \
	sda1,b,8,1	sda2,b,8,2	sda3,b,8,3	sda4,b,8,4 \
	sdb,b,8,16 \
	sdb1,b,8,17	sdb2,b,8,18	sdb3,b,8,19	sdb4,b,8,20 \
	sdc,b,8,32 \
	sdc1,b,8,33	sdc2,b,8,34	sdc3,b,8,35	sdc4,b,8,36 \
	sdd,b,8,48 \
	sdd1,b,8,49	sdd2,b,8,50	sdd3,b,8,51	sdd4,b,8,52 \
	sde,b,8,64 \
	sde1,b,8,65	sde2,b,8,66	sde3,b,8,67	sde4,b,8,68 \
	sdf,b,8,80 \
	sdf1,b,8,81	sdf2,b,8,82	sdf3,b,8,83	sdf4,b,8,84 \
	\
	mem,c,1,1       kmem,c,1,2      null,c,1,3 \
	zero,c,1,5      random,c,1,8    urandom,c,1,9 \
	ram0,b,1,0      ram1,b,1,1      ram2,b,1,2      ram3,b,1,3 \
	\
	tty,c,5,0       console,c,5,1 \
	cua0,c,205,17   cua1,c,205,16 \
	ttyS0,c,204,17  ttyS1,c,204,16 \
	ttyAM0,c,204,16 ttyAM1,c,204,17 \
	\
	ptyp0,c,2,0     ptyp1,c,2,1     ptyp2,c,2,2     ptyp3,c,2,3 \
	ptyp4,c,2,4     ptyp5,c,2,5     ptyp6,c,2,6     ptyp7,c,2,7 \
	ptyp8,c,2,8     ptyp9,c,2,9     ptypa,c,2,10    ptypb,c,2,11 \
	ptypc,c,2,12    ptypd,c,2,13    ptype,c,2,14    ptypf,c,2,15 \
	\
	ptyq0,c,2,16    ptyq1,c,2,17    ptyq2,c,2,18    ptyq3,c,2,19 \
	ptyq4,c,2,20    ptyq5,c,2,21    ptyq6,c,2,22    ptyq7,c,2,23 \
	ptyq8,c,2,24    ptyq9,c,2,25    ptyqa,c,2,26    ptyqb,c,2,27 \
	ptyqc,c,2,28    ptyqd,c,2,29    ptyqe,c,2,30    ptyqf,c,2,31 \
	\
	ptyr0,c,2,32    ptyr1,c,2,33    ptyr2,c,2,34    ptyr3,c,2,35 \
	ptyr4,c,2,36    ptyr5,c,2,37    ptyr6,c,2,38    ptyr7,c,2,39 \
	ptyr8,c,2,40    ptyr9,c,2,41    ptyra,c,2,42    ptyrb,c,2,43 \
	ptyrc,c,2,44    ptyrd,c,2,45    ptyre,c,2,46    ptyrf,c,2,47 \
	\
	ptys0,c,2,48    ptys1,c,2,49    ptys2,c,2,50    ptys3,c,2,51 \
	ptys4,c,2,52    ptys5,c,2,53    ptys6,c,2,54    ptys7,c,2,55 \
	ptys8,c,2,56    ptys9,c,2,57    ptysa,c,2,58    ptysb,c,2,59 \
	ptysc,c,2,60    ptysd,c,2,61    ptyse,c,2,62    ptysf,c,2,63 \
	\
	ttyp0,c,3,0     ttyp1,c,3,1     ttyp2,c,3,2     ttyp3,c,3,3 \
	ttyp4,c,3,4     ttyp5,c,3,5     ttyp6,c,3,6     ttyp7,c,3,7 \
	ttyp8,c,3,8     ttyp9,c,3,9     ttypa,c,3,10    ttypb,c,3,11 \
	ttypc,c,3,12    ttypd,c,3,13    ttype,c,3,14    ttypf,c,3,15 \
	\
	ttyq0,c,3,16    ttyq1,c,3,17    ttyq2,c,3,18    ttyq3,c,3,19 \
	ttyq4,c,3,20    ttyq5,c,3,21    ttyq6,c,3,22    ttyq7,c,3,23 \
	ttyq8,c,3,24    ttyq9,c,3,25    ttyqa,c,3,26    ttyqb,c,3,27 \
	ttyqc,c,3,28    ttyqd,c,3,29    ttyqe,c,3,30    ttyqf,c,3,31 \
	\
	ttyr0,c,3,32    ttyr1,c,3,33    ttyr2,c,3,34    ttyr3,c,3,35 \
	ttyr4,c,3,36    ttyr5,c,3,37    ttyr6,c,3,38    ttyr7,c,3,39 \
	ttyr8,c,3,40    ttyr9,c,3,41    ttyra,c,3,42    ttyrb,c,3,43 \
	ttyrc,c,3,44    ttyrd,c,3,45    ttyre,c,3,46    ttyrf,c,3,47 \
	\
	ttys0,c,3,48    ttys1,c,3,49    ttys2,c,3,50    ttys3,c,3,51 \
	ttys4,c,3,52    ttys5,c,3,53    ttys6,c,3,54    ttys7,c,3,55 \
	ttys8,c,3,56    ttys9,c,3,57    ttysa,c,3,58    ttysb,c,3,59 \
	ttysc,c,3,60    ttysd,c,3,61    ttyse,c,3,62    ttysf,c,3,63 \
	\
	mtd0,c,90,0     mtdr0,c,90,1    mtdblock0,b,31,0 \
	mtd1,c,90,2     mtdr1,c,90,3    mtdblock1,b,31,1 \
	mtd2,c,90,4     mtdr2,c,90,5    mtdblock2,b,31,2 \
	mtd3,c,90,6     mtdr3,c,90,7    mtdblock3,b,31,3 \
	mtd4,c,90,8     mtdr4,c,90,9    mtdblock4,b,31,4 \
	mtd5,c,90,10    mtdr5,c,90,11   mtdblock5,b,31,5 \
	mtd6,c,90,12    mtdr6,c,90,13   mtdblock6,b,31,6 \
	mtd7,c,90,14    mtdr7,c,90,15   mtdblock7,b,31,7 \
	mtd8,c,90,16    mtdr8,c,90,17   mtdblock8,b,31,8 \
	mtd9,c,90,18    mtdr9,c,90,19   mtdblock9,b,31,9 \
	\
	rtc,c,10,135 \
	lcdtxt,c,120,0 \
	keypad,c,121,0 \
	mixer,c,14,0 \
	mixer1,c,14,16 \
	sequencer,c,14,1 \
	music,c,14,8 \
	midi00,c,14,2 \
	midi01,c,14,18 \
	midi02,c,14,34 \
	midi03,c,14,50 \
	dsp,c,14,3 \
	dspleft,p,0,0 dspright,p,0,0 \
	audio,c,14,4 \
	dsp1,c,14,19 \
	audio1,c,14,20 \
	sndstat,c,14,6 \
	key,c,122,0 \
	watchdog,c,10,130 \
	ipsec,c,36,10 \
	ledman,c,126,0 \
	ppp,c,108,0

FLASH_DEVICES = \
	boot,c,90,0 \
	key,c,90,0 \
	ethmac,c,90,0 \
	bootarg,c,90,0 \
	data,c,90,2 \
	config,c,90,4 \
	image,c,90,6 \
	all,c,90,8

.PHONY: romfs all clean

all:

clean:

romfs:
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
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) -S $(ROMFS_SOURCE_BASE) /
	-chmod a+x $(ROMFSDIR)/bin/*
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)
	cp $(RAMDISK) $(RAMDISKZ)

	cp $(RAMDISKZ) $(IMAGE)
	cat $(KERNELZ) >> $(IMAGE)
	
	echo -ne "\000" >> $(IMAGE)
	echo -n $(VERSIONPKG) >> $(IMAGE)
	echo -ne "\000" >> $(IMAGE)
	echo -n $(HW_VENDOR) >> $(IMAGE)
	echo -ne "\000" >> $(IMAGE)
	echo -n $(HW_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISKZ) /tftpboot/ 2> /dev/null; \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi
