#
#	Makefile -- Build instructions for Netburner/MOD5272
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

DIRS = 

ROMFS_DIRS = bin \
	dev \
	etc etc/config \
	home home/httpd home/httpd/cgi-bin \
	lib \
	mnt \
	proc \
	usr \
	var

DEVICES = \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65 \
	mem,c,1,1      kmem,c,1,2         null,c,1,3       ram0,b,1,0 \
	\
	ram1,b,1,1 \
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
	mtd0,b,31,0    mtd1,b,31,1        mtd2,b,31,2      mtd3,b,31,3 \
	mtd4,b,31,4    mtd5,b,31,5 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	zero,c,1,5     random,c,1,8       urandom,c,1,9	\
	\
	watchdog,c,10,130 \
	\
	qspi0,c,126,0   qspi1,c,126,1   qspi2,c,126,2   qspi3,c,126,3 \
	\
	rtf0,c,150,0 rtf1,c,150,1 rtf2,c,150,2 \
	rtf3,c,150,3 rtf4,c,150,4 rtf5,c,150,5 \
	\
	rtsock0,c,121,0 rtsock1,c,121,1 rtsock2,c,121,2 \
	rtsock3,c,121,3 rtsock4,c,121,4 rtsock5,c,121,5


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
	dirs=$(DIRS) ; for i in $$dirs; do make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/config/passwd
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/services
	$(ROMFSINST) /etc/issue
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version


#
# in making the image we have to add the romfs into the 
# system image
# The blkmem driver will find it at the end of the data section.
# There have been several ways to actually
# add the rom fils system into the image
# In this port _end_romfs is required to produce the start of the
# ram area.
# this used to be calcualted by setting
#  romfs_size =       some number; in romfs.ld
#
#
image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.ramvec\
		--set-section-flags=.romvec=CONTENTS,ALLOC,LOAD,READONLY,CODE \
		$(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(CROSS_COMPILE)objcopy -O srec --remove-section=.ramvec\
		--set-section-flags=.romvec=CONTENTS,ALLOC,LOAD,READONLY,CODE \
		$(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.s19
	objcopy -O srec -I binary \
			--change-addresses=0x2000000 \
			--set-start=0x0 \
			$(IMAGEDIR)/image.bin $(IMAGEDIR)/image.s19

vendor_flash:
	$(ROOTDIR)/bin/make_flash
