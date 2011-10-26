#
#	Makefile -- Build instructions for SnapGear/PRO
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ   = $(IMAGEDIR)/imagez.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

DIRS = 

ROMFS_DIRS = bin dev dev/flash etc etc/config etc/default home lib mnt proc \
             usr var home/httpd home/httpd/cgi-bin

DEVICES = \
	tty,c,5,0      cua0,c,5,64        cua1,c,5,65  \
	mem,c,1,1      kmem,c,1,2         null,c,1,3   \
	\
	ram0,b,1,0     ram1,b,1,1 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	ptyq0,c,2,16   ptyq1,c,2,17       ptyq2,c,2,18     ptyq3,c,2,19 \
	ptyq4,c,2,20   ptyq5,c,2,21       ptyq6,c,2,22     ptyq7,c,2,23 \
	ptyq8,c,2,24   ptyq9,c,2,25       ptyqa,c,2,26     ptyqb,c,2,27 \
	ptyqc,c,2,28   ptyqd,c,2,29       ptyqe,c,2,30     ptyqf,c,2,31 \
	\
	ptyr0,c,2,32   ptyr1,c,2,33       ptyr2,c,2,34     ptyr3,c,2,35 \
	ptyr4,c,2,36   ptyr5,c,2,37       ptyr6,c,2,38     ptyr7,c,2,39 \
	ptyr8,c,2,40   ptyr9,c,2,41       ptyra,c,2,42     ptyrb,c,2,43 \
	ptyrc,c,2,44   ptyrd,c,2,45       ptyre,c,2,46     ptyrf,c,2,47 \
	\
	ptys0,c,2,48   ptys1,c,2,49       ptys2,c,2,50     ptys3,c,2,51 \
	ptys4,c,2,52   ptys5,c,2,53       ptys6,c,2,54     ptys7,c,2,55 \
	ptys8,c,2,56   ptys9,c,2,57       ptysa,c,2,58     ptysb,c,2,59 \
	ptysc,c,2,60   ptysd,c,2,61       ptyse,c,2,62     ptysf,c,2,63 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	ttyq0,c,3,16   ttyq1,c,3,17       ttyq2,c,3,18     ttyq3,c,3,19 \
	ttyq4,c,3,20   ttyq5,c,3,21       ttyq6,c,3,22     ttyq7,c,3,23 \
	ttyq8,c,3,24   ttyq9,c,3,25       ttyqa,c,3,26     ttyqb,c,3,27 \
	ttyqc,c,3,28   ttyqd,c,3,29       ttyqe,c,3,30     ttyqf,c,3,31 \
	\
	ttyr0,c,3,32   ttyr1,c,3,33       ttyr2,c,3,34     ttyr3,c,3,35 \
	ttyr4,c,3,36   ttyr5,c,3,37       ttyr6,c,3,38     ttyr7,c,3,39 \
	ttyr8,c,3,40   ttyr9,c,3,41       ttyra,c,3,42     ttyrb,c,3,43 \
	ttyrc,c,3,44   ttyrd,c,3,45       ttyre,c,3,46     ttyrf,c,3,47 \
	\
	ttys0,c,3,48   ttys1,c,3,49       ttys2,c,3,50     ttys3,c,3,51 \
	ttys4,c,3,52   ttys5,c,3,53       ttys6,c,3,54     ttys7,c,3,55 \
	ttys8,c,3,56   ttys9,c,3,57       ttysa,c,3,58     ttysb,c,3,59 \
	ttysc,c,3,60   ttysd,c,3,61       ttyse,c,3,62     ttysf,c,3,63 \
	\
	zero,c,1,5     random,c,1,8       urandom,c,1,9 \
	\
	ipsec,c,36,10 \
	ledman,c,126,0 \
	hifn0,c,28,0 \
	ppp,c,108,0

ifdef CONFIG_BLK_DEV_BLKMEM

	DEVICES += \
		rom0,b,31,0    rom1,b,31,1        rom2,b,31,2      rom3,b,31,3 \
		rom4,b,31,4    rom5,b,31,5        rom6,b,31,6      rom7,b,31,7 \
		rom8,b,31,8    rom9,b,31,9

	FLASH_DEVICES = \
		config,b,31,5 \
		image,b,31,4 \
		bootarg,b,31,2 \
		ethmac,b,31,3 \
		boot,b,31,1 \
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

	FLASH_DEVICES = \
		boot,c,90,0 \
		bootarg,c,90,2 \
		ethmac,c,90,4 \
		config,c,90,6 \
		spare,c,90,8 \
		image,c,90,10 \
		all,c,90,12
endif

ifeq ($(filter-out linux-2.0%, $(LINUXDIR)),)
	DEVICES += console,c,4,0
else
	DEVICES += console,c,5,1
endif

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
	dirs=$(DIRS) ; for i in $$dirs; do make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) ../../SecureEdge/romfs /

	$(ROMFSINST) -p 755 ../../SecureEdge/romfs/etc/default/ip-down \
	/etc/default/ip-down
	$(ROMFSINST) -p 755 ../../SecureEdge/romfs/etc/default/ip-up \
	/etc/default/ip-up
	$(ROMFSINST) -p 755 ../../SecureEdge/romfs/etc/default/dhcpcd-change \
	/etc/default/dhcpcd-change

	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/rc
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
			$(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot
	gzip -c -9 $(IMAGE) > $(IMAGEZ)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGEZ) /tftpboot
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null

vendor_flash:
	$(ROOTDIR)/bin/make_flash

