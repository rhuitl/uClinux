#
# This Makefile fragment incorporates all the declarations and rules
# common to products for this vendor.
#
# It is included by <product>/Makefile 
#

.PHONY: image.clean image.tag image.copy image.dir image.linuz image.arm.zimage image.cramfs
.PHONY: image.sh.mot image.sh.abs image.flash image.configs
.PHONY: romfs.dirs romfs.symlinks romfs.default romfs.recover romfs.rc romfs.version

# Note: These must all be used only in romfs.post::
.PHONY: romfs.no-ixp400-modules romfs.ixp425-microcode romfs.ixp425-boot

# Stop dd from being so noisy
DD=dd 2>/dev/null

# Override this if necessary
FLASH_DEVICES ?= \
	boot,c,90,0 \
	ethmac,c,90,0 \
	bootarg,c,90,0 \
	config,c,90,2 \
	image,c,90,4 \
	all,c,90,6

# You probably want to add this to ROMFS_DIRS
DEFAULT_ROMFS_DIRS := bin sbin dev/flash dev/pts etc/config lib/modules proc var \
             home/httpd/cgi-bin usr/bin usr/sbin

image.clean:
	rm -f mkcramfs mksquashfs mksquashfs7z
	rm -f addr.txt

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

.PHONY: mksquashfs
mksquashfs:
	make -C $(ROOTDIR)/user/squashfs/squashfs-tools mksquashfs
	ln -fs $(ROOTDIR)/user/squashfs/squashfs-tools/mksquashfs .

.PHONY: mksquashfs7z
mksquashfs7z:
	make -C $(ROOTDIR)/user/squashfs/squashfs-tools mksquashfs7z
	ln -fs $(ROOTDIR)/user/squashfs/squashfs-tools/mksquashfs7z .

# Tags an image with vendor,product,version and adds the checksum
image.tag:
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)

image.size.zimage:
	@if [ `cat $(ZIMAGE) | wc -c` -gt $(ZIMAGESIZE) ]; then \
		echo "Error: $(ZIMAGE) size is greater than $(ZIMAGESIZE)"; \
		exit 1; \
	fi

image.size:
	@if [ `cat $(IMAGE) | wc -c` -gt $(IMAGESIZE) ]; then \
		echo "Error: $(IMAGE) size is greater than $(IMAGESIZE)"; \
		exit 1; \
	fi

image.copy:
	@set -e; for i in $(IMAGE) $(KERNELZ) $(IMAGEDIR)/sh.mot $(IMAGEDIR)/sh.abs; do \
		[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] && continue; \
		[ -f $$i ] || continue; \
		echo cp $$i /tftpboot; \
		cp $$i /tftpboot; \
	done
	@[ -n "$(NO_BUILD_INTO_TFTPBOOT)" ] || ( echo cp $(IMAGE) /tftpboot/$(CONFIG_PRODUCT).bin; cp $(IMAGE) /tftpboot/$(CONFIG_PRODUCT).bin )

image.dir:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/man[1-9]

# Create ZIMAGE as vmlinux -> objcopy -> $(ZIMAGE)
image.linuz:
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/linux.bin
	gzip -c -9 < $(IMAGEDIR)/linux.bin >$(ZIMAGE)

# Create ZIMAGE as arm/arm/boot/zImage
image.arm.zimage:
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(ZIMAGE)

image.cramfs: mkcramfs
	./mkcramfs -z -r $(ROMFSDIR) $(ROMFSIMG)

image.squashfs: mksquashfs
	rm -f $(ROMFSIMG); mksquashfs=`pwd`/mksquashfs; cd $(ROMFSDIR); \
	$$mksquashfs . $(ROMFSIMG) -all-root -noappend $(SQUASH_ENDIAN)

image.squashfs7z: mksquashfs7z
	rm -f $(ROMFSIMG); mksquashfs7z=`pwd`/mksquashfs7z; cd $(ROMFSDIR); \
	$$mksquashfs7z . $(ROMFSIMG) -all-root -noappend $(SQUASH_ENDIAN)

# Create (possibly) mbr + cramfs + zimage/linuz
image.bin:
	cat $(MBRIMG) $(ROMFSIMG) $(ZIMAGE) >$(IMAGE)

addr.txt: $(ROOTDIR)/$(LINUXDIR)/vmlinux
	$(CROSS)nm $(ROOTDIR)/$(LINUXDIR)/vmlinux | \
		grep " __bss_start$$" | \
		cut -d' ' -f1 | xargs printf "0x%s\n" >$@
	@echo ROMFS@`cat $@`

image.sh.mot: addr.txt
	@ADDR=`cat addr.txt`; \
        $(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
          --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
          --set-section-flags=.romfs=alloc,load,data   \
		  -O srec \
          $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/sh.mot

image.sh.abs: addr.txt
	ADDR=`cat addr.txt`; \
        $(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
          --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
          --set-section-flags=.romfs=alloc,load,data   \
          $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/sh.abs

image.flash:
	[ ! -f $(ROOTDIR)/boot/boot.bin ] || $(MAKE) vendor_flashbin

image.configs:
	@rm -rf configs
	@mkdir -p configs
	cp $(ROOTDIR)/.config configs/config.device
	cp $(ROOTDIR)/config/.config configs/config.vendor-$(patsubst linux-%,%,$(CONFIG_LINUXDIR)) 
	cp $(ROOTDIR)/$(CONFIG_LINUXDIR)/.config configs/config.$(CONFIG_LINUXDIR)
	cp $(ROOTDIR)/$(CONFIG_LIBCDIR)/.config configs/config.$(CONFIG_LIBCDIR)
	tar czf $(IMAGEDIR)/configs.tar.gz configs
	@rm -rf configs
	
romfs.dirs:
	mkdir -p $(ROMFSDIR)
	@for i in $(ROMFS_DIRS); do \
		mkdir -p $(ROMFSDIR)/$$i; \
	done

romfs.symlinks:
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/mnt /mnt
	$(ROMFSINST) -s /var/tmp/log /dev/log

romfs.default:
	$(ROMFSINST) ../romfs /

romfs.recover:
	$(ROMFSINST) ../romfs.recover /

romfs.rc:
	$(ROMFSINST) /etc/rc; \
	[ ! -f filesystems ] || $(ROMFSINST) /etc/filesystems

romfs.no-ixp400-modules:
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400/ixp400_*.o

romfs.ixp425-microcode:
	[ ! -f $(ROOTDIR)/modules/ixp425/ixp400-2.0/IxNpeMicrocode.dat ] || $(ROMFSINST) -d $(ROOTDIR)/modules/ixp425/ixp400-2.0/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat
	[ ! -f $(ROOTDIR)/modules/ixp425/ixp400-2.1/IxNpeMicrocode.dat ] || $(ROMFSINST) -d $(ROOTDIR)/modules/ixp425/ixp400-2.1/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat
	[ ! -f $(ROOTDIR)/modules/ixp425/ixp400-2.4/IxNpeMicrocode.dat ] || $(ROMFSINST) -d $(ROOTDIR)/modules/ixp425/ixp400-2.4/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat

romfs.ixp425-boot:
	-$(ROMFSINST) -d $(ROOTDIR)/boot/ixp425/bios.bin /boot/biosplus.bin
	-$(ROMFSINST) -d $(ROOTDIR)/boot/ixp425/boot.bin /boot/bootplus.bin

romfs.version:
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version
