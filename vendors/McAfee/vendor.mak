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
.PHONY: romfs.no-ixp400-modules romfs.ixp425-microcode romfs.ixp425-boot romfs.nooom

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

SGKEY ?= $(HOME)/keys/sgkey.pem

# OVFTool location
OVFTOOL_IN_PATH = $(shell which ovftool)
ifneq ($(OVFTOOL_IN_PATH),)
OVFTOOL	  = $(OVFTOOL_IN_PATH)
endif
OVFTOOL	  ?= $(HOME)/tools/ovftool/ovftool

COMMON_ROMFS_DIRS =
ifdef CONFIG_SYSFS
COMMON_ROMFS_DIRS += sys
endif
ifdef CONFIG_PROC_FS
COMMON_ROMFS_DIRS += proc
endif
ifdef CONFIG_USER_UDEV
COMMON_ROMFS_DIRS += lib/udev/devices/pts lib/udev/devices/flash
else
COMMON_ROMFS_DIRS += dev dev/pts dev/flash
endif

# You probably want to add this to ROMFS_DIRS
DEFAULT_ROMFS_DIRS := $(COMMON_ROMFS_DIRS) \
	bin sbin etc/config lib/modules var \
	home/httpd/cgi-bin usr/bin usr/sbin

FACTORY_ROMFS_DIRS := $(COMMON_ROMFS_DIRS) \
	bin etc lib mnt usr var

# Generate list of processes to kill during a netflash upgrade
NETFLASH_KILL_LIST_FILE ?= etc/netflash_kill_list.txt

# Processes that are killed on all platforms
NETFLASH_KILL_LIST_y ?= 
NETFLASH_KILL_LIST_$(CONFIG_PROP_AUTHD_AUTHD)			+= authd
NETFLASH_KILL_LIST_$(CONFIG_USER_ZEBRA_BGPD_BGPD)		+= bgpd
NETFLASH_KILL_LIST_$(CONFIG_USER_CLAMAV_CLAMAV)			+= clamav
NETFLASH_KILL_LIST_$(CONFIG_USER_CLAMAV_CLAMD)			+= clamd
NETFLASH_KILL_LIST_$(CONFIG_USER_CLAMAV_CLAMSMTP)		+= clamsmtpd
NETFLASH_KILL_LIST_$(CONFIG_USER_CRON_CRON)			+= cron
NETFLASH_KILL_LIST_$(CONFIG_USER_DHCPD_DHCPD)			+= dhcpd
NETFLASH_KILL_LIST_$(CONFIG_USER_DHCP_ISC_SERVER_DHCPD)		+= dhcpd
NETFLASH_KILL_LIST_$(CONFIG_USER_DHCP_ISC_RELAY_DHCRELAY)	+= dhcrelay
NETFLASH_KILL_LIST_$(CONFIG_USER_DNSMASQ_DNSMASQ)		+= dnsmasq
NETFLASH_KILL_LIST_$(CONFIG_USER_DNSMASQ2_DNSMASQ2)		+= dnsmasq
NETFLASH_KILL_LIST_$(CONFIG_USER_FLATFSD_FLATFSD)		+= flatfsd
NETFLASH_KILL_LIST_$(CONFIG_USER_FROX_FROX)			+= frox
NETFLASH_KILL_LIST_$(CONFIG_USER_SSH_SSHKEYGEN)			+= gen-keys
NETFLASH_KILL_LIST_$(CONFIG_PROP_HTTPSCERTGEN_HTTPSCERTGEN)	+= https-certgen
NETFLASH_KILL_LIST_$(CONFIG_USER_IDB_IDB)			+= idb
NETFLASH_KILL_LIST_$(CONFIG_USER_BUSYBOX_BUSYBOX)		+= klogd
NETFLASH_KILL_LIST_$(CONFIG_PROP_NFLOGD_NFLOGD)			+= nflogd
NETFLASH_KILL_LIST_$(CONFIG_USER_NTPD_NTPD)			+= ntpd
NETFLASH_KILL_LIST_$(CONFIG_PROP_AUTHD_AUTHD)			+= proxy80
NETFLASH_KILL_LIST_$(CONFIG_USER_ZEBRA_RIPD_RIPD)		+= ripd
NETFLASH_KILL_LIST_$(CONFIG_USER_SIPROXD_SIPROXD)		+= siproxd
NETFLASH_KILL_LIST_$(CONFIG_PROP_AUTHD_AUTHD)			+= sgadnsd
NETFLASH_KILL_LIST_$(CONFIG_USER_SNMPD_SNMPD)			+= snmpd
NETFLASH_KILL_LIST_$(CONFIG_USER_NETSNMP_SNMPD)			+= snmpd
NETFLASH_KILL_LIST_$(CONFIG_USER_SNORT_SNORT)			+= snort
NETFLASH_KILL_LIST_$(CONFIG_USER_SNORT_SNORT)			+= snort-inline
NETFLASH_KILL_LIST_$(CONFIG_USER_SQUID_SQUID)			+= squid
NETFLASH_KILL_LIST_$(CONFIG_USER_SSH_SSHKEYGEN)			+= ssh-keygen
NETFLASH_KILL_LIST_$(CONFIG_PROP_STATSD_STATSD)			+= statsd
NETFLASH_KILL_LIST_$(CONFIG_USER_BUSYBOX_BUSYBOX)		+= syslogd
NETFLASH_KILL_LIST_$(CONFIG_USER_LINUXIGD_LINUXIGD)		+= upnpd
NETFLASH_KILL_LIST_$(CONFIG_USER_ZEBRA_ZEBRA_ZEBRA)		+= zebra


image.clean:
	rm -f mkcramfs mksquashfs mksquashfs7z
	rm -f addr.txt

mkcramfs: $(ROOTDIR)/user/cramfs/mkcramfs.c
	$(HOSTCC) -o $@ -I$(ROOTDIR)/$(LINUXDIR)/include $< -lz

.PHONY: mksquashfs
mksquashfs:
	CC=$(HOSTCC) CFLAGS=$(HOSTCFLAGS) EXTRA_CFLAGS= make -C $(ROOTDIR)/user/squashfs-new/squashfs-tools mksquashfs
	ln -fs $(ROOTDIR)/user/squashfs-new/squashfs-tools/mksquashfs .

.PHONY: mksquashfs7z
mksquashfs7z:
	make -C $(ROOTDIR)/user/squashfs/squashfs-tools mksquashfs7z
	ln -fs $(ROOTDIR)/user/squashfs/squashfs-tools/mksquashfs7z .

# Tags an image with vendor,product,version and adds the checksum
image.tag:
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
ifdef CONFIG_USER_NETFLASH_CRYPTO
	if [ -f $(SGKEY) ] ; then \
		$(ROOTDIR)/user/netflash/cryptimage -k $(SGKEY) -f $(IMAGE) ; \
		printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE) ; \
	fi
endif
ifdef CONFIG_USER_NETFLASH_SHA256
	cat $(IMAGE) | $(ROOTDIR)/user/netflash/sha256sum -b >> $(IMAGE)
	printf '\0%s\0%s\0%s' $(VERSIONPKG) $(HW_VENDOR) $(HW_PRODUCT) >>$(IMAGE)
endif
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

# Create ZIMAGE as vmlinux -> objcopy (include bss) -> $(ZIMAGE)
image.bsslinuz:
	$(CROSS)objcopy -O binary --set-section-flags .bss=load,contents $(ROOTDIR)/$(LINUXDIR)/vmlinux $(IMAGEDIR)/linux.bin
	gzip -c -9 < $(IMAGEDIR)/linux.bin >$(ZIMAGE)

# Create ZIMAGE as arm/arm/boot/zImage
image.arm.zimage:
	cp $(ROOTDIR)/$(LINUXDIR)/arch/arm/boot/zImage $(ZIMAGE)

image.mips.zimage:
	gzip -c -9 < $(ROOTDIR)/$(LINUXDIR)/arch/mips/boot/vmlinux.bin >$(ZIMAGE)

image.i386.zimage:
	cp $(ROOTDIR)/$(LINUXDIR)/arch/i386/boot/bzImage $(ZIMAGE)

image.mips.vmlinux:
	cp $(ROOTDIR)/$(LINUXDIR)/vmlinux $(VMLINUX)

# Create a 16MB file for testing
image.16mb:
	dd if=/dev/zero of=$(ROMFSDIR)/16MB bs=1000000 count=16

image.16mb.rm:
	rm -f $(ROMFSDIR)/16MB

image.cramfs: mkcramfs
	./mkcramfs -z -r $(ROMFSDIR) $(ROMFSIMG)

image.squashfs: mksquashfs
	rm -f $(ROMFSIMG); mksquashfs=`pwd`/mksquashfs; cd $(ROMFSDIR); \
	$$mksquashfs . $(ROMFSIMG) -all-root -noappend $(SQUASH_ENDIAN)

image.squashfs7z: mksquashfs7z
	rm -f $(ROMFSIMG); mksquashfs7z=`pwd`/mksquashfs7z; cd $(ROMFSDIR); \
	$$mksquashfs7z . $(ROMFSIMG) -all-root -noappend $(SQUASH_ENDIAN)

image.romfs:
	rm -f $(ROMFSIMG)
	genromfs -f $(ROMFSIMG) -d $(ROMFSDIR)

# Create (possibly) mbr + cramfs + zimage/linuz
image.bin:
	cat $(MBRIMG) $(ROMFSIMG) $(SHIM) $(ZIMAGE) >$(IMAGE)

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
	-cp $(ROOTDIR)/$(CONFIG_LIBCDIR)/.config configs/config.$(CONFIG_LIBCDIR)
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
	[ -d $(ROMFSDIR)/sbin ] || $(ROMFSINST) -s bin /sbin

# Override this if necessary
VENDOR_ROMFS_DIR ?= ..

romfs.default:
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/romfs /
	chmod 755 $(ROMFSDIR)/etc/default/dhcpcd-change
	chmod 755 $(ROMFSDIR)/etc/default/ip-*
ifeq ($(CONFIG_LIBCDIR),glibc)
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/nsswitch.conf /etc/nsswitch.conf
endif
ifdef CONFIG_USER_NETFLASH_NETFLASH
	rm -f $(ROMFSDIR)/$(NETFLASH_KILL_LIST_FILE)
	for p in $(sort $(NETFLASH_KILL_LIST_y)) ; do echo $$p >> $(ROMFSDIR)/$(NETFLASH_KILL_LIST_FILE); done
endif

romfs.recover:
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/romfs.recover /

romfs.factory:
	$(ROMFSINST) $(VENDOR_ROMFS_DIR)/romfs/etc/services /etc/services

# This is the old way. Just install the static rc file
romfs.rc.static:
	if [ -f rc-$(CONFIG_LANGUAGE) ]; then \
		$(ROMFSINST) /etc/rc-$(CONFIG_LANGUAGE) /etc/rc; \
	else \
		$(ROMFSINST) /etc/rc; \
	fi
	[ ! -f filesystems ] || $(ROMFSINST) /etc/filesystems

# This is the new way. Generate it dynamically.
romfs.rc:
	echo
	pwd
	echo
	echo rc-$(CONFIG_LANGUAGE)
	echo
	if [ -f $(ROOTDIR)/prop/configdb/rcgen ]; then \
		[ ! -f rc-$(CONFIG_LANGUAGE) ] || ( echo "*** Error: Static rc-$(CONFIG_LANGUAGE) file exists, but trying to use dynamic rc file"; exit 1 ) ; \
		[ ! -f rc ] || echo "*** Warning: Static rc file exists, but using dynamic rc file" ; \
		tclsh $(ROOTDIR)/prop/configdb/rcgen $(ROOTDIR) >$(ROMFSDIR)/etc/rc ; \
	else \
		$(ROMFSINST) /etc/rc; \
	fi
	[ ! -f filesystems ] || $(ROMFSINST) /etc/filesystems

romfs.inittab:
	[ ! -f inittab ] || echo "*** Warning: Static inittab file exists, but using dynamic inittab file"
	$(ROMFSINST) -e CONFIG_USER_INETD_INETD -a "inet:unknown:/bin/inetd" /etc/inittab

romfs.no-ixp400-modules:
	rm -f $(ROMFSDIR)/lib/modules/*/kernel/ixp425/ixp400-*/ixp400_*.o

romfs.ixp425-microcode:
	$(ROMFSINST) -e CONFIG_IXP400_LIB_2_0 -d $(ROOTDIR)/modules/ixp425/ixp400-2.0/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat
	$(ROMFSINST) -e CONFIG_IXP400_LIB_2_1 -d $(ROOTDIR)/modules/ixp425/ixp400-2.1/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat
	$(ROMFSINST) -e CONFIG_IXP400_LIB_2_4 -d $(ROOTDIR)/modules/ixp425/ixp400-2.4/IxNpeMicrocode.dat /etc/IxNpeMicrocode.dat

romfs.ixp425-boot:
ifneq ($(strip $(BOOTLOADER)),)
	$(ROMFSINST) -d $(BOOTLOADERBIOS) /boot/biosplus.bin
	$(ROMFSINST) -d $(BOOTLOADER) /boot/bootplus.bin
else 
	-$(ROMFSINST) -d $(ROOTDIR)/boot/ixp425/bios.bin /boot/biosplus.bin
	-$(ROMFSINST) -d $(ROOTDIR)/boot/ixp425/boot.bin /boot/bootplus.bin
endif

romfs.boot:
# Skip this whole target for host builds
ifndef HOSTBUILD
ifneq ($(strip $(BOOTLOADER)),)
	$(ROMFSINST) -d $(BOOTLOADER) /boot/boot.bin
else 
	-$(ROMFSINST) -d $(ROOTDIR)/boot/boot.bin /boot/boot.bin
endif
endif

romfs.version:
	echo "$(VERSIONSTR) -- " $(BUILD_START_STRING) > $(ROMFSDIR)/etc/version
	echo "$(HW_VENDOR)/$(HW_PRODUCT)" > $(ROMFSDIR)/etc/hwdetails

romfs.cryptokey:
ifdef CONFIG_USER_NETFLASH_CRYPTO
	if [ -f $(SGKEY) ] ; then \
		openssl rsa -in $(SGKEY) -pubout > $(ROMFSDIR)/etc/publickey.pem ; \
	fi
endif

romfs.nooom:
	[ ! -x $(ROMFSDIR)/bin/no_oom ] || ( ( cd $(ROMFSDIR) && mkdir -p .no_oom ) && for i in `echo ${CONFIG_USER_NOOOM_BINARIES}` ; do [ -x $(ROMFSDIR)/$$i ] && [ x`readlink $(ROMFSDIR)/$$i` != x/bin/no_oom ] && mv $(ROMFSDIR)/$$i $(ROMFSDIR)/.no_oom/`basename $$i` && ln -s /bin/no_oom $(ROMFSDIR)/$$i || "NOTICE: $$i not present in romfs" ; done )

romfs.post:: romfs.nooom

# OVF generation for VM targets
ovf:
	if [ -x $(OVFTOOL) ] ; then	\
		rm -rf $(IMAGEDIR)/$(HDDBASE)-ovf;	\
		mkdir $(IMAGEDIR)/$(HDDBASE)-ovf;	\
		(cd $(IMAGEDIR)/$(HDDBASE)-ovf; $(OVFTOOL) ../$(HDDBASE)/$(IMGBASE).vmx $(IMGBASE).ovf);	\
		rm -f $(IMAGEDIR)/$(HDDBASE)-ovf.zip;	\
		(cd $(IMAGEDIR)/$(HDDBASE)-ovf; zip -r ../$(HDDBASE)-ovf.zip .); \
	fi
