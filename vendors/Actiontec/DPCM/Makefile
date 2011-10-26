#
#	Makefile -- Build instructions for Actiontec Dual PC modem
#

ROMFSIMG = $(IMAGEDIR)/romfs.img

ROMFS_DIRS = bin dev etc htdocs proc var

DEVICES = \
	tty,c,5,0        console,c,5,1    \
	\
	ledman,c,126,0   \
	\
	mtd0,c,90,0      mtd1,c,90,2      mtd2,c,90,4      mtd3,c,90,6      \
        mtd4,c,90,8      \
	\
	mtdblock0,b,90,0 mtdblock1,b,90,2 mtdblock2,b,90,4 mtdblock3,b,90,6 \
        mtdblock4,b,90,8 \
	\
	ppp,c,108,0      \
	\
	null,c,1,3       \
	\
	ptyp0,c,2,0      ptyp1,c,2,1      ptyp2,c,2,2      ptyp3,c,2,3      \
	ptyp4,c,2,4      ptyp5,c,2,5      ptyp6,c,2,6      ptyp7,c,2,7      \
	ptyp8,c,2,8      ptyp9,c,2,9      ptypa,c,2,10     ptypb,c,2,11     \
	ptypc,c,2,12     ptypd,c,2,13     ptype,c,2,14     ptypf,c,2,15     \
	\
	ttyp0,c,3,0      ttyp1,c,3,1      ttyp2,c,3,2      ttyp3,c,3,3      \
	ttyp4,c,3,4      ttyp5,c,3,5      ttyp6,c,3,6      ttyp7,c,3,7      \
	ttyp8,c,3,8      ttyp9,c,3,9      ttypa,c,3,10     ttypb,c,3,11     \
	ttypc,c,3,12     ttypd,c,3,13     ttype,c,3,14     ttypf,c,3,15     \
	\
	tty0,c,4,0       \
	ttyS0,c,4,64     ttyS1,c,4,65 \
	\
	zero,c,1,5       random,c,1,8     urandom,c,1,9

clean:

romfs:
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	# these permissions are needed for openpty and family to work
	# on non-ptmx ptys
	chmod 620 $(ROMFSDIR)/dev/@[pt]ty[pqrsPQRS][0-9a-f],*
	$(ROMFSINST) -s /bin /sbin
	$(ROMFSINST) -s ../var/etc/dnsmasq.conf /etc/dnsmasq.conf
	$(ROMFSINST) -s ../var/etc/passwd /etc/passwd
	$(ROMFSINST) -s ../var/etc/ppp /etc/ppp
	$(ROMFSINST) -s ../var/etc/resolv.conf /etc/resolv.conf
	$(ROMFSINST) -s ../var/etc/sysconfig /etc/sysconfig
	touch $(ROMFSDIR)/etc/group
	$(ROMFSINST) -p 755 /linuxrc
	for i in scripts/*; do \
		$(ROMFSINST) -p 755 $$i /bin/`basename $$i`; \
	done
	chmod 755 \
	  $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/defaultconfig/ppp/ip-up \
	  $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/defaultconfig/ppp/ip-down \
	  $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/defaultconfig/sysconfig/*
	tar czf $(ROMFSDIR)/etc/defaultconfig.tar.gz \
	  -C $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/defaultconfig \
	  .
	$(ROMFSINST) ../../Generic/romfs/etc/services /etc/services
	case "$(LINUXDIR)" in \
	*2.4.*) ;; \
	*) echo "ttyS0:linux:/bin/sh" >> $(ROMFSDIR)/etc/inittab ;; \
	esac
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS_COMPILE)objcopy -O binary $(ROOTDIR)/$(LINUXDIR)/linux \
		$(IMAGEDIR)/linux
	gzip -c $(IMAGEDIR)/linux > $(IMAGEDIR)/linuz
