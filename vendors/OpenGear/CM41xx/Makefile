#
#	Makefile -- Build instructions for OpenGear/CM41xx
#

KERNELZ  = $(IMAGEDIR)/zImage
RAMDISK  = $(IMAGEDIR)/ramdisk
RAMDISKZ = $(IMAGEDIR)/ramdisk.gz
IMAGE    = $(IMAGEDIR)/image.bin

ROMFS_DIRS = \
	bin \
	dev dev/flash \
	etc etc/config etc/default etc/default/users \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	mnt \
	proc \
	sbin \
	usr usr/bin usr/sbin \
	var

DEVICES = \
	mem,c,1,1       kmem,c,1,2      null,c,1,3 \
	zero,c,1,5      random,c,1,8    urandom,c,1,9 \
	ram0,b,1,0      ram1,b,1,1      ram2,b,1,2      ram3,b,1,3 \
	\
	tty,c,5,0	console,c,5,1 \
	ttyS0,c,4,64	ttyS1,c,4,65	ttyS2,c,4,66	ttyS3,c,4,67 \
	ttyS4,c,4,68	ttyS5,c,4,69	ttyS6,c,4,70	ttyS7,c,4,71 \
	ttyS8,c,4,72	ttyS9,c,4,73	ttyS10,c,4,74 	ttyS11,c,4,75 \
	ttyS12,c,4,76	ttyS13,c,4,77	ttyS14,c,4,78	ttyS15,c,4,79 \
	ttyS16,c,4,80	ttyS17,c,4,81	ttyS18,c,4,82	ttyS19,c,4,83 \
	ttyS20,c,4,84	ttyS21,c,4,85	ttyS22,c,4,86	ttyS23,c,4,87 \
	ttyS24,c,4,88	ttyS25,c,4,89	ttyS26,c,4,90	ttyS27,c,4,91 \
	ttyS28,c,4,92	ttyS29,c,4,93	ttyS30,c,4,94	ttyS31,c,4,95 \
	ttyS32,c,4,96	ttyS33,c,4,97	ttyS34,c,4,98	ttyS35,c,4,99 \
	ttyS36,c,4,100	ttyS37,c,4,101	ttyS38,c,4,102	ttyS39,c,4,103 \
	ttyS40,c,4,104	ttyS41,c,4,105	ttyS42,c,4,106	ttyS43,c,4,107 \
	ttyS44,c,4,108	ttyS45,c,4,109	ttyS46,c,4,110	ttyS47,c,4,111 \
	\
	port01,c,4,64	port02,c,4,65	port03,c,4,66	port04,c,4,67 \
	port05,c,4,68	port06,c,4,69	port07,c,4,70	port08,c,4,71 \
	port09,c,4,72	port10,c,4,73	port11,c,4,74	port12,c,4,75 \
	port13,c,4,76	port14,c,4,77	port15,c,4,78	port16,c,4,79 \
	port17,c,4,80	port18,c,4,81	port19,c,4,82	port20,c,4,83 \
	port21,c,4,84	port22,c,4,85	port23,c,4,86	port24,c,4,87 \
	port25,c,4,88	port26,c,4,89	port27,c,4,90	port28,c,4,91 \
	port29,c,4,92	port30,c,4,93	port31,c,4,94	port32,c,4,95 \
	port33,c,4,96	port34,c,4,97	port35,c,4,98	port36,c,4,99 \
	port37,c,4,100	port38,c,4,101	port39,c,4,102	port40,c,4,103 \
	port41,c,4,104	port42,c,4,105	port43,c,4,106	port44,c,4,107 \
	port45,c,4,108	port46,c,4,109	port47,c,4,110	port48,c,4,111 \
	\
	cua0,c,5,64	cua1,c,5,65	cua2,c,5,66	cua3,c,5,67 \
	cua4,c,5,68	cua5,c,5,69	cua6,c,5,70	cua7,c,5,71 \
	cua8,c,5,72	cua9,c,5,73	cua10,c,5,74 	cua11,c,5,75 \
	cua12,c,5,76	cua13,c,5,77	cua14,c,5,78	cua15,c,5,79 \
	cua16,c,5,80	cua17,c,5,81	cua18,c,5,82	cua19,c,5,83 \
	cua20,c,5,84	cua21,c,5,85	cua22,c,5,86	cua23,c,5,87 \
	cua24,c,5,88	cua25,c,5,89	cua26,c,5,90	cua27,c,5,91 \
	cua28,c,5,92	cua29,c,5,93	cua30,c,5,94	cua31,c,5,95 \
	cua32,c,5,96	cua33,c,5,97	cua34,c,5,98	cua35,c,5,99 \
	cua36,c,5,100	cua37,c,5,101	cua38,c,5,102	cua39,c,5,103 \
	cua40,c,5,104	cua41,c,5,105	cua42,c,5,106	cua43,c,5,107 \
	cua44,c,5,108	cua45,c,5,109	cua46,c,5,110	cua47,c,5,111 \
	\
	ttyAM0,c,204,16	cuamm0,c,205,16 \
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
	watchdog,c,10,130 \
	ipsec,c,36,10 \
	ledman,c,126,0 \
	rtc,c,10,135 \
	ppp,c,108,0

FLASH_DEVICES = \
	boot,c,90,0 \
	ethmac,c,90,0 \
	bootarg,c,90,0 \
	config,c,90,2 \
	configblock,b,31,1 \
	image,c,90,4 \
	all,c,90,6

all:

clean:
	-rm -f mkcramfs

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
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) -s /etc/config/passwd /etc/passwd
	$(ROMFSINST) -s /etc/config/group /etc/group
	$(ROMFSINST) -s /etc/config/ntpd.conf /etc/ntpd.conf
	$(ROMFSINST) -s /etc/config/TZ /etc/TZ
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) -A "inet:" -a "inet:unknown:/bin/inetd" /etc/inittab
	$(ROMFSINST) -A "fltd:" -a "fltd:unknown:/bin/flatfsd" /etc/inittab
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	chmod a+x $(ROMFSDIR)/bin/*
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(KERNELZ)
	./mkcramfs -z -r $(ROMFSDIR) $(RAMDISK)
	cp $(RAMDISK) $(RAMDISKZ)
	cp $(RAMDISKZ) $(IMAGE)
	cat $(KERNELZ) >> $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISKZ) /tftpboot/ 2> /dev/null; \
		cp $(IMAGE) /tftpboot/ 2> /dev/null; \
	fi

