#
#	Makefile -- Build instructions for SecureEdge/SecureEdgePCMCIA
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

ROMFS_DIRS = dev/usb
USB_DEVICES = dabusb0,180,240
EXTRA_DEVICES = video,c,81,0 video0,c,81,0 video1,c,81,1 \
		cardpro0,c,125,0 cardpro1,c,125,1
ifdef CONFIG_BLK_DEV_SD
	EXTRA_DEVICES += \
		sda,b,8,0	sda1,b,8,1	sda2,b,8,2 \
		sda3,b,8,3	sda4,b,8,4	sda5,b,8,5 \
		sdb,b,8,16	sdb1,b,8,17	sdb2,b,8,18 \
		sdb3,b,8,19	sdb4,b,8,20	sdb5,b,8,21 \
		sdc,b,8,32	sdc1,b,8,33	sdc2,b,8,34 \
		sdc3,b,8,35	sdc4,b,8,36	sdc5,b,8,37 \
		sdd,b,8,48	sdd1,b,8,49	sdd2,b,8,50 \
		sdd3,b,8,51	sdd4,b,8,52	sdd5,b,8,53 \
		sde,b,8,64	sde1,b,8,65	sde2,b,8,66 \
		sde3,b,8,67	sde4,b,8,68	sde5,b,8,69 \
		sdf,b,8,80	sdf1,b,8,81	sdf2,b,8,82 \
		sdf3,b,8,83	sdf4,b,8,84	sdf5,b,8,85
endif

all clean:
	$(MAKE) -C ../SecureEdge2580 $@

image:
	$(ROMFSINST) /etc/fstab
	$(MAKE) -C ../SecureEdge2580 $@

romfs:
	$(MAKE) -C ../SecureEdge2580 $@
	for i in $(ROMFS_DIRS); do \
		mkdir -p $(ROMFSDIR)/$$i; \
	done
	for i in $(USB_DEVICES); do \
		touch $(ROMFSDIR)/dev/usb/@$$i; \
	done
	for i in $(EXTRA_DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) -p 555 /etc/rc
	$(ROMFSINST) /etc/fstab
	echo "/etc/rc.d/rc.pcmcia start" >> $(ROMFSDIR)/etc/default/start
	echo "insmod usbcore" >> $(ROMFSDIR)/etc/default/start
	echo "insmod usb-ohci" >> $(ROMFSDIR)/etc/default/start
	echo "insmod usb-storage" >> $(ROMFSDIR)/etc/default/start
	echo "mount -t usbdevfs none /proc/bus/usb" >> $(ROMFSDIR)/etc/default/start
	#echo "insmod sarlib" >> $(ROMFSDIR)/etc/default/start
	#echo "insmod speedtch" >> $(ROMFSDIR)/etc/default/start
	#echo "insmod videodev" >> $(ROMFSDIR)/etc/default/start
	#echo "insmod ov511" >> $(ROMFSDIR)/etc/default/start

