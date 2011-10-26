#
#	Makefile -- Build instructions for SecureEdge MP3
#

ROMFSIMG  = $(IMAGEDIR)/romfs.img
ROMFSIMG2 = $(IMAGEDIR)/usr.bin
IMAGE     = $(IMAGEDIR)/image.bin
IMAGEZ    = $(IMAGEDIR)/imagez.bin
ELFIMAGE  = $(IMAGEDIR)/image.elf

DIRS =

ROMFS_DIRS = bin dev dev/flash etc etc/config etc/default home lib mnt proc \
             usr var usr/mp3 usr/bin

DEVICES = \
	tty,c,5,0 \
	console,c,5,1 \
	cua0,c,5,64 \
	cua1,c,5,65 \
	mem,c,1,1 \
	kmem,c,1,2 \
	null,c,1,3 \
	ram0,b,1,0 \
	ram1,b,1,1 \
	ptyp0,c,2,0 \
	ptyp1,c,2,1 \
	ptyp2,c,2,2 \
	ptyp3,c,2,3 \
	ptyp4,c,2,4 \
	ptyp5,c,2,5 \
	rom0,b,31,0 \
	rom1,b,31,1 \
	rom2,b,31,2 \
	rom3,b,31,3 \
	rom4,b,31,4 \
	rom5,b,31,5 \
	rom6,b,31,6 \
	rom7,b,31,7 \
	rom8,b,31,8 \
	rom9,b,31,9 \
	tty0,c,4,0 \
	tty1,c,4,1 \
	tty2,c,4,2 \
	tty3,c,4,3 \
	ttyS0,c,4,64 \
	ttyS1,c,4,65 \
	ttyp0,c,3,0 \
	ttyp1,c,3,1 \
	ttyp2,c,3,2 \
	ttyp3,c,3,3 \
	ttyp4,c,3,4 \
	ttyp5,c,3,5 \
	hda,b,3,0 \
	hda1,b,3,1 \
	hda2,b,3,2 \
	hdb,b,3,64 \
	zero,c,1,5 \
	random,c,1,8 \
	urandom,c,1,9 \
	ledman,c,126,0 \
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
	audio,c,14,4 \
	dsp1,c,14,19 \
	audio1,c,14,20 \
	sndstat,c,14,6 \
	dspleft,c,14,14 \
	dspright,c,14,15 \
	mbus,c,127,0

FLASH_DEVICES = \
	config,b,31,5 \
	image,b,31,4 \
	bootarg,b,31,2 \
	ethmac,b,31,3 \
	boot,b,31,1 \
	all,b,31,6

# Files to put into the second ROMFS
ROMFS2 = bin/nmbd bin/smbd
ZFILES = bin/nmbd bin/smbd

all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done

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
	dirs=$(DIRS) ; for i in $$dirs; do  make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/fstab
	$(ROMFSINST) ../MP3romfs.template /
	case "$(LINUXDIR)" in \
	*2.4*) $(ROMFSINST) fstab-2.4.x /etc/fstab ;; \
	esac
	[ -e $(ROMFSDIR)/usr/msp ] || mkdir $(ROMFSDIR)/usr/msp
	[ -e $(ROMFSDIR)/usr/logs ] || mkdir $(ROMFSDIR)/usr/logs
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	$(ROMFSINST) /etc/default/smb.conf # override the samba default
	@for i in $(ZFILES); do \
		[ ! -f $(ROMFSDIR)/$$i ] || $(CROSS)flthdr -z $(ROMFSDIR)/$$i;\
	done
	[ -d "$(ROMFSDIR)2" ] || mkdir -p "$(ROMFSDIR)2"
	@for i in $(ROMFS2); do \
		[ -f $(ROMFSDIR)/$$i ] || continue; \
		mv -f $(ROMFSDIR)/$$i $(ROMFSDIR)2/`basename $$i`; \
	done
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
            $(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot
	gzip -c -9 $(IMAGE) > $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGEZ) /tftpboot
	genromfs -v -V "ROMdisk2" -f $(ROMFSIMG2) -d $(ROMFSDIR)2
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(ROMFSIMG2) /tftpboot
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null

vendor_flash:
	$(ROOTDIR)/bin/make_flash

