#
# Makefile -- Build instructions for Insight XC2VP7 board
#

# ROMFSIMG = $(IMAGEDIR)/root.romfs
# IMAGE    = $(IMAGEDIR)/image.bin
# IMAGEZ	 = $(IMAGEDIR)/imagez.bin
# ELFIMAGE = $(IMAGEDIR)/linux
ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ	 = $(IMAGEDIR)/imagez.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

DIRS = 

ROMFS_DIRS = bin dev dev/flash etc home lib mnt proc usr var

DEVICES =								      \
	tty,c,5,0      console,c,5,1   mem,c,1,1     kmem,c,1,2    null,c,1,3 \
									      \
	ttyS0,c,4,64   ttyS1,c,4,65					      \
									      \
	zero,c,1,5     random,c,1,8    urandom,c,1,9			      \
									      \
	ram0,b,1,0	ram1,b,1,1					      \
	leds,c,10,169							      \
	gpio,c,10,185							      \
	ppp,c,108,0							      \
									      \
	ptyp0,c,2,0    ptyp1,c,2,1     ptyp2,c,2,2   ptyp3,c,2,3	      \
	ptyp4,c,2,4    ptyp5,c,2,5     ptyp6,c,2,6   ptyp7,c,2,7	      \
	ptyp8,c,2,8    ptyp9,c,2,9     ptypa,c,2,10  ptypb,c,2,11	      \
	ptypc,c,2,12   ptypd,c,2,13    ptype,c,2,14  ptypf,c,2,15	      \
									      \
	ttyp0,c,3,0    ttyp1,c,3,1     ttyp2,c,3,2   ttyp3,c,3,3	      \
	ttyp4,c,3,4    ttyp5,c,3,5     ttyp6,c,3,6   ttyp7,c,3,7	      \
	ttyp8,c,3,8    ttyp9,c,3,9     ttypa,c,3,10  ttypb,c,3,11	      \
	ttypc,c,3,12   ttypd,c,3,13    ttype,c,3,14  ttypf,c,3,15	   

DEVICES +=   \
	mtd0,c,90,0	mtdr0,c,90,1	mtdblock0,b,31,0	\
	mtd1,c,90,2	mtdr1,c,90,3	mtdblock1,b,31,1	\
	mdt2,c,90,4	mtdr2,c,90,5	mtdblock2,b,31,2	\
	mtd3,c,90,6	mtdr3,c,90,7	mtdblock3,b,31,3	\
	mtd4,c,90,8 	mtdr4,c,90,9	mtdblock4,b,31,4	\
	mtd5,c,90,10 	mtdr5,c,90,11	mtdblock5,b,31,5	\
	mtd6,c,90,12 	mtdr6,c,90,13	mtdblock6,b,31,6	\
	mtd7,c,90,14 	mtdr7,c,90,15	mtdblock7,b,31,7


FLASH_DEVICES = \
	boot,c,90,0	\
	bootarg,c,90,2	\
	ethmac,c,90,4	\
	config,c,90,6	\
	spare,c,90,8	\
	image,c,90,10	\
	jffs2,c,90,12	\
	all,c,90,14

all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  $(MAKE) -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || $(MAKE) -C $$i clean; done

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
	for i in $(DIRS); do $(MAKE) -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	#$(ROMFSINST) ../romfs /
	#$(ROMFSINST) -p 755 ../romfs/etc/default/ip-up /etc/default/ip-up
	#$(ROMFSINST) -p 755 ../romfs/etc/default/ip-down /etc/default/ip-down
	#$(ROMFSINST) -p 755 ../romfs/etc/default/dhcpcd-change /etc/default/dhcpcd-change
	$(ROMFSINST) -s /bin /sbin
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	#for f in $(ROMFSDIR)/etc/default{,-static}/inittab; do  \
		#grep -v ^dns: $$f >$(ROMFSDIR)/temp-file;       \
		#mv -f $(ROMFSDIR)/temp-file $$f;                        \
	#done
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/README
	$(ROMFSINST) $(XILINX_COMMON)/passwd /etc/passwd
	$(ROMFSINST) $(XILINX_COMMON)/group /etc/group
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version
	#touch $(ROMFSDIR)/etc/singleboot


image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	$(CROSS)flthdr $(ROMFSDIR)/bin/*
	$(CROSS)flthdr $(ROMFSDIR)/lib/lib[0-9].so
	for i in $(RAM_FILES) ; do \
		[ ! -f $(ROMFSDIR)/$$i ] || $(CROSS)flthdr -r $(ROMFSDIR)/$$i ; \
	done

	for i in $(ROMFSDIR)/bin/* ; do \
		$(CROSS)flthdr -z $$i; \
	done

	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
			$(IMAGEDIR)/linux.bin
	gzip -9 < $(IMAGEDIR)/linux.bin | dd conv=sync ibs=4 > $(IMAGEDIR)/linuxz.bin
	@case "$(LINUXDIR)" in \
	XXXXX*2.4.*XXXXX) \
		echo "Building gzip imagez.bin"; \
		cat $(IMAGEDIR)/linuxz.bin $(ROMFSIMG) | gzip -9 > $(IMAGEZ); \
		;;\
	*) \
		echo "Building normal imagez.bin"; \
		cat $(IMAGEDIR)/linuxz.bin $(ROMFSIMG) > $(IMAGEZ); \
		;;\
	esac
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep "\.bss"` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	mb-objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 
	mb-objcopy -O binary --remove-section=.stab --remove-section=.stabstr $(ELFIMAGE) $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGEZ) /tftpboot

vendor_flash:
	$(ROOTDIR)/bin/make_flash
