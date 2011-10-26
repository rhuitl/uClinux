#
#	Makefile -- Build instructions for Intec/WildFire (ColdFire 5282)
#	            based on Motorola/M5282C3
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
ELFIMAGE = $(IMAGEDIR)/image.elf
BOOTDIR  = $(ROMFSDIR)/boot
EXT2IMG  = $(IMAGEDIR)/rootfs.bin

ROMFS_DIRS = \
	bin \
	dev \
	etc etc/config etc/default etc/dhcpc \
	home home/httpd home/httpd/cgi-bin \
	lib \
	mnt \
	proc sys \
	usr \
	var

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
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) ../../Generic/romfs /
	$(ROMFSINST) ../../Generic/big/inittab /etc/inittab
	$(ROMFSINST) romfs_extra /
	if [ "$(CONFIG_BLK_DEV_INITRD)" = "y" ]; then \
		ln -sf bin/init $(ROMFSDIR)/linuxrc; \
	fi
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

# Create the raw kernel image: linux.bin
image.linux:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
	  $(IMAGEDIR)/linux.bin

# Create image.bin and image.elf
# These are not currently used, but might be useful
# for debugging
image.bin: image.linux
	genromfs -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${4}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null

# Create a root filesystem on an SD card
#
image.sdcard: image.linux
	sudo sh mount-sdcard.sh /mnt/sdext
	sudo sh make-rootfs-devs.sh dev.txt /mnt/sdext
	sudo mkdir -p /mnt/sdext/boot
	sudo cp -R $(ROMFSDIR)/* /mnt/sdext
	sudo cp $(IMAGEDIR)/linux.bin /mnt/sdext/boot
	sudo umount /mnt/sdext
	
image: image.sdcard
