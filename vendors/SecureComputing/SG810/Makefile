#############################################################################
#
#	Makefile -- Build instructions for SecureComputing/SG810
#
#############################################################################

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

#############################################################################

LINUXFILE = bzImage
LINUXIMG  = $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/$(LINUXFILE)

VENDDIR    = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.

PREFIX     = $(IMAGEDIR)/CF

# the number of 512 byte blocks in config partition (4096 = 2Mb)
CONFIG     = 4096

KERNELZ    = $(LINUXFILE)
RAMDISKZ   = cramfs.img.gz
ISOFILE  = $(IMAGEDIR)/image.iso
ISODIR     = $(ROOTDIR)/iso

#############################################################################

DIRS = 

ROMFS_DIRS = \
	bin boot \
	dev dev/flash dev/pts \
	etc etc/config \
	home home/httpd home/httpd/cgi-bin \
	lib lib/modules \
	proc \
	tmp \
	sbin \
	usr usr/bin usr/sbin \
	var var/run var/log var/tmp var/lock var/empty

DEVICES += $(DEVICE_PTY_16)

FLASH_DEVICES = \
	image,b,22,0 \
	config,b,22,2

#############################################################################

all: prereq
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done
	rm -f romfs.img ext3.img cramfs.img mkcramfs

romfs: romfs_dev
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) $(LINUXIMG) /boot/vmlinuz
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version

#############################################################################
#
# tool we need for build host based versions of the programs
#

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

lilo:
	chmod +x lilo

#############################################################################
#
# re copy the kernel so that "make linux image" works
#

image: romfs.img cf-images
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(PREFIX)-recover.bin /tftpboot/.
	gzip -9 -f -c cramfs.img > $(RAMDISKZ) 
	mkdir -p $(ISODIR)/boot/isolinux
	cp isolinux.bin $(ISODIR)/boot/isolinux/
	cp boot.msg $(ISODIR)/boot/isolinux/
	cp isolinux.cfg $(ISODIR)/boot/isolinux/
	cp $(LINUXIMG) $(ISODIR)/boot/isolinux/
	cp $(RAMDISKZ) $(ISODIR)/boot/isolinux/initrd.gz
	mkisofs -J -o $(ISOFILE) -b boot/isolinux/isolinux.bin \
		-c boot/isolinux/boot.cat -no-emul-boot \
		-boot-load-size 4 -boot-info-table $(ISODIR)

#############################################################################
#
# make images for various sizes of compact flash,  check your geometry,
# you may need to add your own here,  remove any your don't want built from
# the cf-images target
#

.PHONY: cf-images extimage-64MB extimage-128MB romfs.img lilo

romfs.img: mkcramfs
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]
	./mkcramfs -z -r $(ROMFSDIR) cramfs.img
	mknbi-linux --append=init=/bin/sh --rootmode=ro --rootdir=/dev/0100 \
			--output=$(PREFIX)-recover.bin $(LINUXIMG) cramfs.img
	genromfs -v -V "ROMdisk" -f romfs.img -d $(ROMFSDIR)

cf-images: extimage-64MB extimage-128MB

extimage-64MB: romfs.img
	#$(MAKE) extimage HEADS=8 SECTORS=32 CYLS=480 IMAGE=$(PREFIX)-64MB.sgu
	$(MAKE) extimage HEADS=4 SECTORS=32 CYLS=978 IMAGE=$(PREFIX)-64MB.sgu

extimage-128MB: romfs.img
	$(MAKE) extimage HEADS=8 SECTORS=32 CYLS=960 IMAGE=$(PREFIX)-128MB.sgu

#############################################################################
#
# Make a lilo bootable compact flash image based on paramters passed in
#

.PHONY: extimage
extimage: lilo
	rm -f mbr.img ext3.img
	@if [ -x /usr/local/bin/root ]; then \
		/usr/local/bin/root sh make-ext3-image $(CYLS) $(HEADS) $(SECTORS) $(CONFIG); \
	else \
		echo '********************************************************'  1>&2 ; \
		echo '********************************************************'  1>&2 ; \
		echo '**                                                    **'  1>&2 ; \
		echo '** Time to make the final compact flash images.       **'  1>&2 ; \
		echo '** For this you need to be "root". You will also need **'  1>&2 ; \
		echo '** a kernel with the loopback device enabled and ext2 **'  1>&2 ; \
		echo '** filesystem support.  Enter the root password below **'  1>&2 ; \
		echo '** if asked,  or an invalid password to abort.        **'  1>&2 ; \
		echo '**                                                    **'  1>&2 ; \
		echo '********************************************************'  1>&2 ; \
		echo '********************************************************'  1>&2 ; \
		echo  1>&2 ; \
		sudo sh make-ext3-image $(CYLS) $(HEADS) $(SECTORS) $(CONFIG); \
	fi
	cat mbr.img ext3.img | gzip -9 > $(IMAGE)
	cp $(IMAGE) $(basename $(IMAGE)).bin.gz
ifdef CONFIG_USER_NETFLASH_HMACMD5
	$(ROOTDIR)/user/netflash/hmacmd5 $(CONFIG_USER_NETFLASH_HMACMD5_KEY) \
				< $(IMAGE) >> $(IMAGE)
else
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
endif
	[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || cp $(IMAGE) /tftpboot/.

# Make sure all of the necessary binaries are available before we start
# Unfortunately this does't actually run until after we have built everything,
# but at least it's friendlier
prereq:
	@which sudo >/dev/null 2>&1 || ( echo "sudo must be installed"; exit 1 )
	@which mkisofs >/dev/null 2>&1 || ( echo "mkisofs must be installed"; exit 1 )
	@which genromfs >/dev/null 2>&1 || ( echo "genromfs must be installed"; exit 1 )
	@which mknbi-linux >/dev/null 2>&1 || ( echo "mknbi-linux must be installed"; exit 1 )
	@if [ ! -x /sbin/sfdisk ]; then echo "/sbin/sfdisk must be installed"; exit 1; fi
	@if [ ! -x /sbin/mke2fs ]; then echo "/sbin/mke2fs must be installed"; exit 1; fi
	@if [ ! -x /sbin/tune2fs ]; then echo "/sbin/tune2fs must be installed"; exit 1; fi

#############################################################################

include $(ROOTDIR)/vendors/config/config.dev
