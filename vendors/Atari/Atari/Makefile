#
#	Makefile -- Build instructions for Atari target
#

RAMDISK  = $(IMAGEDIR)/ramdisk
KERNELZ  = $(IMAGEDIR)/vmlinux.gz

DIRS = 

ROMFS_DIRS = \
	bin \
	dev \
	etc etc/config etc/default \
	home home/httpd home/httpd/cgi-bin \
	lib \
	mnt mnt/workspace mnt/flash \
	proc \
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
	$(ROMFSINST) ../../Generic/httpd /home/httpd
	$(ROMFSINST) ../../Generic/big/inittab /etc/inittab
	if [ $(CONFIG_BLK_DEV_INITRD) = "y" ]; then \
		ln -sf bin/init $(ROMFSDIR)/linuxrc; \
	fi
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(ROMFSDIR)/lib/modules
	genext2fs -b 4096 -f dev.txt -d $(ROMFSDIR) $(RAMDISK)
	#gzip -9 -f $(RAMDISK)
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux.gz $(KERNELZ)
	if [ -d /tftpboot ]; then \
		cp $(KERNELZ) /tftpboot/ 2> /dev/null; \
		cp $(RAMDISK) /tftpboot/ 2> /dev/null; \
	fi

