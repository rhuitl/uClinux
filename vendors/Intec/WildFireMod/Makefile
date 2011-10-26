#
#	Makefile -- Build instructions for Intec/WildFireMod (ColdFire 5282)
#	            based on Motorola/M5282C3
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
JFFS2IMG = $(IMAGEDIR)/jffs2.img.bin
IMAGE    = $(IMAGEDIR)/image.bin
ELFIMAGE = $(IMAGEDIR)/image.elf
BOOTDIR  = $(ROMFSDIR)/boot
EXT2IMG  = $(IMAGEDIR)/rootfs.bin

DIRS = 

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

image.linux.gz: image.linux
	gzip -9 <$(IMAGEDIR)/linux.bin >$(IMAGEDIR)/linux.gz.bin
	

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

# Create a jffs2 filesystem
image.jffs2: image.linux
	mkfs.jffs2 -o $(JFFS2IMG) -b -q -e 65536 -d $(ROMFSDIR) -D device.tab --pad=3145728

# Create a root filesystem on an SD card
# Note: You will need to change the kernel cmdline
#       to "root=0x7901 rw" for this to work
image.sdcard: image.linux
	sudo sh mount-sdcard.sh /mnt/sdext
	sudo sh make-rootfs-devs.sh dev.txt /mnt/sdext
	sudo mkdir -p /mnt/sdext/boot
	sudo cp -R $(ROMFSDIR)/* /mnt/sdext
	sudo cp $(IMAGEDIR)/linux.bin /mnt/sdext/boot
	sudo umount /mnt/sdext
	
# Choose one of the following two options
#
# 1. Create a filesystem on an SD card (previously prepared with prep-sd-card.sh)
#    In this case, you must include "root=0xFE01 rw" on the kernel command line
#
image: image.sdcard

# 2. Create linux.gz.bin and image.jffs2.bin which can be downloaded and
#    written to the external flash with dnfl.
#    In this case you must include "root=/dev/mtdblock1 rootfstype=jffs2"
#    on the kernel command line.
#    And then download and write the images to flash with:
#    dBUG> dnfl xf linux.gz.bin jffs2.img.bin
#
#image: image.linux.gz image.jffs2
