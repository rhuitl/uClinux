#
#	Makefile -- Build instructions for Serra/MFC3000
#	based on Motorola/M5282C3 and Avnet/AVNET5282
#	by Daniel Alomar (daniel.alomar@gmail.com)
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

DIRS = 

# If we want to use Hotplug, we must add etc/hotplug etc/hotplug/usb to ROMFS_DIRS

ROMFS_DIRS = \
	bin \
	dev \
	etc etc/default etc/dhcpc \
	home home/httpd home/httpd/cgi-bin home/conf home/apli home/dades home/apli home/dintre home/musb \
	lib \
	mnt \
	proc proc/sys \
	usr \
	var

DEVICES = \
	tty,c,5,0	console,c,5,1	cua0,c,5,64	cua1,c,5,65 \
	mem,c,1,1	kmem,c,1,2	null,c,1,3	zero,c,1,5 \
	\
	random,c,1,8	urandom,c,1,9\
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
	ttyS0,c,4,64	ttyS1,c,4,65 ttyS2,c,4,66\
	\
	rom0,b,31,0	rom1,b,31,1	rom2,b,31,2	rom3,b,31,3 \
	rom4,b,31,4	rom5,b,31,5	rom6,b,31,6	rom7,b,31,7 \
	rom8,b,31,8	rom9,b,31,9  \
	\
	mtd1,c,90,2	mtdr1,c,90,3	mtdblock1,b,31,1 \
	mtd2,c,90,4	mtdr2,c,90,5	mtdblock2,b,31,2 \
	mtd3,c,90,6	mtdr3,c,90,7	mtdblock3,b,31,3 \
	mtd4,c,90,8	mtdr4,c,90,9	mtdblock4,b,31,4 \
	\
	ioex,c,61,0 \
	mfc3,c,62,5 \
	ipsec,c,36,10 \
	\
	usb0,c,127,0	usb1,c,127,1	usb2,c,127,2	usb3,c,127,3  \
  \
  sda0,b,8,0      sda1,b,8,1      sda2,b,8,2      sda3,b,8,3 \
	sdb0,b,8,0      sdb1,b,8,1      sdb2,b,8,2      sdb3,b,8,3

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
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) ../romfs /
	# Begin HOTPLUG
		#$(ROMFSINST) ../sbin /sbin		# Binaris/scripts hotplug
		# $(ROMFSINST) ../hotplug/usb /etc/hotplug/usb # Script usb
		# ln -s /bin/modprobe $(ROMFSDIR)/sbin/modprobe	# link modprobe to sbin (KMOD)
	# End HOTPLUG
	$(ROMFSINST) ../httpd /home/httpd
	$(ROMFSINST) ../conf /home/conf	# samba configuration file under rw
	$(ROMFSINST) ../musb /home/musb	# added external usb modules
	chmod 777 $(ROMFSDIR)/home/dades		# 777 to dades
	chmod 777 $(ROMFSDIR)/home/dintre		# 777 to dintre
	ln -s /home/conf/resolv.conf $(ROMFSDIR)/etc/resolv.conf # Link to flash
	ln -s /home/conf/inetd.conf $(ROMFSDIR)/etc/inetd.conf # Link to flash
	ln -s /home/conf/dhcpc/dhcpcd-eth0.cache $(ROMFSDIR)/etc/dhcpc/dhcpcd-eth0.cache # Cache dhcpc
	ln -s /home/conf/dhcpc/dhcpcd-eth0.info $(ROMFSDIR)/etc/dhcpc/dhcpcd-eth0.info   # Info dhcpc
	# smbd and nmbd to flash
		# ln -s /home/samba/smbd $(ROMFSDIR)/bin/smbd
		# ln -s /home/samba/nmbd $(ROMFSDIR)/bin/nmbd
	# end smbd and nmbd to flash
	$(ROMFSINST) ../big/inittab /etc/inittab
	$(ROMFSINST) ../big/rc /etc/rc
	$(ROMFSINST) ../big/rcd /home/rcd
	if [ $(CONFIG_BLK_DEV_INITRD) = "y" ]; then \
		ln -sf bin/init $(ROMFSDIR)/linuxrc; \
	fi
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
	  $(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null
	rm -rf jffs2
	mv $(ROMFSDIR)/home jffs2
	mkfs.jffs2 -b -o $(IMAGEDIR)/jffs2.img -d jffs2
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGEDIR)/jffs2.img /tftpboot
	


