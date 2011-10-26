#
#	Makefile -- Build instructions for SnapGear/SnapGear7100
#
#	This target is built with the uClib library and cramfs
#

ROMFSIMG   = $(IMAGEDIR)/romfs.img
IMAGE      = $(IMAGEDIR)/image.bin
KERNELZ    = $(IMAGEDIR)/linuz.bin

LINUXFILE  = bzImage
MBRIMG     = $(IMAGEDIR)/mbr.img
E2FSIMG    = $(IMAGEDIR)/e2fs.img
RAMDISK    = /dev/ram0
ROMDISKMNT = $(ROOTDIR)/images/mnt1
RAMDISKMNT = $(ROOTDIR)/images/mnt2
VENDDIR    = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.


DIRS =

ROMFS_DIRS = \
	boot \
	bin \
	dev dev/flash dev/pts \
	etc etc/config etc/default \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	proc \
	usr \
	var

DEVICES += $(DEVICE_PTY_16)

FLASH_DEVICES = \
	boot,c,90,0 \
	bootarg,c,90,0 \
	ethmac,c,90,0 \
	image,b,93,0 \
	config,b,93,2 \
	all,b,93,0

dep:

all:

clean:
	-rm -f mkcramfs

romfs: romfs_dev
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	rm -rf $(ROMFSDIR)/sbin
	$(ROMFSINST) -s ./bin /sbin
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	-$(ROMFSINST) ../httpd /home/httpd ; \
	#
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	case "$(LINUXDIR)" in \
	*2.4.*) ;; \
	*) echo "ttyS0:linux:/bin/sh" >> $(ROMFSDIR)/etc/inittab ;; \
	esac
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/lilo.conf
	$(ROMFSINST) /boot/message
	-$(ROMFSINST) /boot/boot.b
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

image: mkcramfs
	#
	# Hack to build both the 64MByte bootloader and the 16MByte bootloader.
	#
	# 16 MByte
	-make -C $(ROOTDIR)/boot clean
	-make -C $(ROOTDIR)/boot
	-cp $(ROOTDIR)/boot/sh4/biosplus.bin $(ROMFSDIR)/boot/biosplus-16MB.bin
	-cp $(ROOTDIR)/boot/sh4/bootplus.bin $(ROMFSDIR)/boot/bootplus-16MB.bin

	# 64 MByte
	-make -C $(ROOTDIR)/boot clean
	-make -C $(ROOTDIR)/boot CONFIG_RAM64MB=y
	-cp $(ROOTDIR)/boot/sh4/biosplus.bin $(ROMFSDIR)/boot/biosplus-64MB.bin
	-cp $(ROOTDIR)/boot/sh4/bootplus.bin $(ROMFSDIR)/boot/bootplus-64MB.bin

	cp config.opts $(ROMFSDIR)/etc/pcmcia/config.opts
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)

	rm -rf $(ROMFSDIR)/man[1-9]
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/vmlinux \
		$(IMAGEDIR)/linux.bin
	gzip -c -9 < $(IMAGEDIR)/linux.bin > $(KERNELZ)
	./mkcramfs -z -r $(ROMFSDIR) $(ROMFSIMG)
	dd if=/dev/zero of=$(MBRIMG) bs=512 count=1
	printf "1,48575,L,*\n,,61,-\n" | /sbin/sfdisk  -uS -C 966 -H 16 -S 4 $(MBRIMG)
	cat $(MBRIMG) $(ROMFSIMG) $(KERNELZ) > $(IMAGE)
#	cat $(ROMFSIMG) $(KERNELZ) > $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(CONFIG_VENDOR) $(CONFIG_PRODUCT) >> $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot

include $(ROOTDIR)/vendors/config/config.dev
