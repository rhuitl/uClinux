#
#	Makefile -- Build instructions for SecureEdge/SecureEdge1100
#

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
IMAGEZ   = $(IMAGEDIR)/imagez.bin
ELFIMAGE = $(IMAGEDIR)/image.elf

CFLAGS += -DSYS_NAME='"SecureEdge/SE1100"'

DIRS = 

ROMFS_DIRS = bin dev dev/flash etc etc/config etc/default home lib mnt proc \
             usr var home/httpd home/httpd/cgi-bin

DEVICES += $(DEVICE_PTY_64)

FLASH_DEVICES = \
	config,b,31,5 \
	image,b,31,4 \
	bootarg,b,31,2 \
	ethmac,b,31,3 \
	boot,b,31,1 \
	all,b,31,6


all:
	for i in $(DIRS) ; do  make -C $$i || exit $? ; done

clean:
	-for i in $(DIRS); do [ ! -d $$i ] || make -C $$i clean; done

romfs: romfs_dev
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	$(ROMFSINST) ../romfs /
	$(ROMFSINST) -p 755 ../romfs/etc/default/ip-up /etc/default/ip-up
	$(ROMFSINST) -p 755 ../romfs/etc/default/ip-down /etc/default/ip-down
	rm $(ROMFSDIR)/etc/default/config
	rm $(ROMFSDIR)/etc/default/dhcpcd-change
	rm $(ROMFSDIR)/etc/default/ip-down
	rm $(ROMFSDIR)/etc/default/ip-up
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) start /etc/default/start
	$(ROMFSINST) /etc/inittab
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
			$(IMAGEDIR)/linux.bin
	cat $(IMAGEDIR)/linux.bin $(ROMFSIMG) > $(IMAGE)
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

include $(ROOTDIR)/vendors/config/config.dev
