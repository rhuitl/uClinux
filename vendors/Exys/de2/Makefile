#
#	Makefile -- Build instructions for Exys/de2
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
BOARDDIR = $(ROOTDIR)/$(LINUXDIR)/arch/m68knommu/platform/68VZ328/de2

DIRS = 

ROMFS_DIRS = bin dev etc home lib mnt proc usr var mnt \
             home/httpd home/httpd/cgi-bin

DEVICES = \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65  \
	mem,c,1,1      kmem,c,1,2         null,c,1,3 \
	\
	ram0,b,1,0     ram1,b,1,1         ram2,b,1,2       ram3,b,1,3 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	mtd0,c,90,0    mtd1,c,90,2        mtd2,c,90,4      mtd3,c,90,6 \
	mtd4,c,90,8    mtd5,c,90,10       mtd6,c,90,12     mtd7,c,90,14 \
	mtdblock0,b,31,0 mtdblock1,b,31,1 mtdblock2,b,31,2 mtdblock3,b,31,3 \
	mtdblock4,b,31,4 mtdblock5,b,31,5 mtdblock6,b,31,6 mtdblock7,b,31,7 \
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
	ipsec,c,36,10  ledman,c,126,0     ppp,c,108,0 \
	fb0,c,29,0     eeprom,c,10,144    ts,c,10,15      fpga,c,61,0


all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done

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
	dirs=$(DIRS) ; for i in $$dirs; do  make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /bin /sbin
	$(ROMFSINST) -s /var/etc/dhcpc /etc/dhcpc
	$(ROMFSINST) -s /var/etc/resolv.conf /etc/resolv.conf
	$(ROMFSINST) /lib/varramfs.img.gz
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/fstab
	$(ROMFSINST) /etc/TZ
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/group
	$(ROMFSINST) -p 744 /etc/ifup.sh
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) ../../Generic/romfs/lib/liberror.txt /lib/liberror.txt
	$(ROMFSINST) ../../Generic/httpd /home/httpd
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS_COMPILE)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux $(IMAGE)
	cat $(ROMFSIMG) >> $(IMAGE)
	$(MAKE) -C $(BOARDDIR)/zimage
	-cp $(IMAGE) $(IMAGEDIR)/zImage.bin /tftpboot
