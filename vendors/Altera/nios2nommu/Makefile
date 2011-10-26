#
#	Makefile -- Build instructions for Altera NiosII with initramfs
#

KERNELZ  = $(IMAGEDIR)/zImage

ROMFS_DIRS = bin sbin dev etc home lib mnt proc usr var sys tmp \
	etc/config etc/default etc/dhcpc home/ftp home/httpd home/httpd/cgi-bin usr/bin usr/sbin usr/share \
	/usr/share/udhcpc

all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done

vendor_hwselect:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) hwselect

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	chmod 777 $(ROMFSDIR)/tmp
	chmod 777 $(ROMFSDIR)/home/ftp
	$(ROMFSINST) ../../Generic/romfs /
	$(ROMFSINST) -s /bin/init /init
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/TZ
	$(ROMFSINST) /etc/passwd
	$(ROMFSINST) /etc/group
	$(ROMFSINST) /etc/hosts
	$(ROMFSINST) /etc/host.conf
	$(ROMFSINST) /etc/ftpwelcome
	$(ROMFSINST) /etc/ftpusers
	$(ROMFSINST) /etc/boa.conf
	$(ROMFSINST) /etc/mime.types
	$(ROMFSINST) /usr/share/udhcpc/default.script
	chmod 777 $(ROMFSDIR)/usr/share/udhcpc/default.script
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	-chmod -R +x $(ROMFSDIR)/bin
	-rm $(ROOTDIR)/$(LINUXDIR)/usr/initramfs_data.cpio.gz
	LDFLAGS="" $(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) $(LINUXTARGET)
	cp $(ROOTDIR)/$(LINUXDIR)/arch/nios2nommu/boot/zImage $(KERNELZ)


