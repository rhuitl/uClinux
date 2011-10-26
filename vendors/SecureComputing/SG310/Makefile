#
#	Makefile -- Build instructions for SecureComputing/SG310
#

ROMFSIMG      = $(IMAGEDIR)/ramdisk
ZIMAGE        = $(IMAGEDIR)/zImage
IMAGE         = $(IMAGEDIR)/image.bin
IMAGESIZE     = 7471104
SQUASH_ENDIAN = -le
BOOTLOADER    = $(PRODUCTDIR)/SG310_v4.1.0p0_20090301.sgb

ROMFS_DIRS    = $(DEFAULT_ROMFS_DIRS)

DEVICES      += $(DEVICE_PTY_64)

FLASH_DEVICES ?= \
        boot,c,90,0 \
        config,c,90,2 \
        image,c,90,4 \
        all,c,90,6 \
        tags,c,90,8 \
        log,c,90,10

# IPSec is rather large and the 310 doesn't have much free RAM, so add it to the netflash kill list
NETFLASH_KILL_LIST_$(CONFIG_USER_FREESWAN)	+= pluto
NETFLASH_KILL_LIST_$(CONFIG_USER_OPENSWAN)	+= pluto

all:

clean: image.clean

romfs: romfs_dev romfs.dirs romfs.symlinks romfs.default romfs.rc romfs.version romfs.boot romfs.cryptokey
	$(ROMFSINST) ../network.init.std /etc/network.init
	$(ROMFSINST) ../firewall.init.std /etc/firewall.init
	$(ROMFSINST) ../statsd.init.min /etc/statsd.init
	$(ROMFSINST) ../pam.init.min /etc/pam.init

image: image.configs image.dir image.arm.zimage image.squashfs7z image.bin image.size image.tag image.copy

include $(ROOTDIR)/vendors/config/config.dev
include ../vendor.mak
