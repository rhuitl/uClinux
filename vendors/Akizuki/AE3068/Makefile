#
#	Makefile -- Build instructions for StrawberryLixux/H8MAX
#

TFTPBOOT = /tftpboot
IMAGE    = $(IMAGEDIR)/aki3068net-image.bin
IMAGEZ   = $(IMAGEDIR)/aki3068net-imagez.bin

ROMFS_DIRS = bin dev etc etc/default home lib mnt proc usr var

DEVICES = \
	console,c,5,1  null,c,1,3 \
	ttySC0,c,204,8 ttySC1,c,204,9 ttySC2,c,204,10

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
	-flthdr -z $(ROMFSDIR)/bin/*
	-flthdr -z $(ROMFSDIR)/sbin/*
	-flthdr -z $(ROMFSDIR)/home/httpd/cgi-bin/*
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
