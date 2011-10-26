#
#	Makefile -- Build instructions for StrawberryLixux/H8MAX
#

include $(ROOTDIR)/$(LINUXDIR)/.config

TFTPBOOT = /tftpboot
IMAGE    = $(IMAGEDIR)/h8max-image.bin
IMAGEZ   = $(IMAGEDIR)/h8max-imagez.bin

ROMFS_DIRS = bin dev etc etc/default home lib mnt proc usr var

DEVICES = \
	console,c,5,1  null,c,1,3 \
	ttySC0,c,204,8 ttySC1,c,204,9 ttySC2,c,204,10\
	\
	hda,b,3,0	hdb,b,3,64	hdc,b,22,0	hdd,b,22,64 \
	hda1,b,3,1	hda2,b,3,2	hda3,b,3,3	hda4,b,3,4 \
	hda5,b,3,5	hda6,b,3,6	hda7,b,3,7	hda8,b,3,8

all:

clean:
	rm -f romfs.img linux.bin

romfs:
	[ -d $(ROMFSDIR) ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	$(ROMFSINST) -s ./bin /sbin
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/tmp/log /dev/log
	> $(ROMFSDIR)/etc/inetd.conf
	echo "boa:unknown:/bin/boa" > $(ROMFSDIR)/etc/default/inittab
	> $(ROMFSDIR)/etc/default/start
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	case "$(LINUXDIR)" in \
	*2.4.*) ;; \
	*) echo "ttyS0:linux:/bin/sh" >> $(ROMFSDIR)/etc/inittab ;; \
	esac
	$(ROMFSINST) /etc/motd
	$(ROMFSINST) /etc/passwd
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
ifeq ($(CONFIG_BINFMT_ZFLAT),y)
	-flthdr -z $(ROMFSDIR)/bin/*
	-flthdr -z $(ROMFSDIR)/sbin/*
	-flthdr -z $(ROMFSDIR)/home/httpd/cgi-bin/*
endif
	genromfs -v -V "ROMdisk" -f romfs.img -d $(ROMFSDIR)
	$(CROSS)objcopy -O binary \
			$(ROOTDIR)/$(LINUXDIR)/linux linux.bin
	cat linux.bin romfs.img > $(IMAGE)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGE) >> $(IMAGE)
	gzip -c -9 $(IMAGE) > $(IMAGEZ)
	$(ROOTDIR)/tools/cksum -b -o 2 $(IMAGEZ) >> $(IMAGEZ)
	@if [ -w "$(TFTPBOOT)/." ]; then \
		echo "Copying images to $(TFTPBOOT) ..."; \
		cp $(IMAGEZ)  $(TFTPBOOT)/. ; \
		cp $(IMAGE)   $(TFTPBOOT)/. ; \
	fi
