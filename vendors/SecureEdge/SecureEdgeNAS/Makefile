#
#	Makefile -- Build instructions for SecureEdge/SecureEdgeNAS
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

DEVICES = \
	hda,b,3,0	hdb,b,3,64 \
	hda1,b,3,1	hda2,b,3,2	hda3,b,3,3	hda4,b,3,4 \
	hda5,b,3,5	hda6,b,3,6	hda7,b,3,7	hda8,b,3,8

all clean image:
	$(MAKE) -C ../SecureEdge2580 $@

romfs:
	$(MAKE) -C ../SecureEdge2580 $@
	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	[ -d $(ROMFSDIR)/mnt/hda ] || mkdir -p $(ROMFSDIR)/mnt/hda
	$(ROMFSINST) /etc/inittab
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/fstab
