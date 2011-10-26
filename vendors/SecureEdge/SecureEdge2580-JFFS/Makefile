#
#	Makefile -- Build instructions for SecureEdge/SecureEdge2580-JFFS
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

all clean image:
	$(MAKE) -C ../SecureEdge2580 $@

romfs:
	$(MAKE) -C ../SecureEdge2580 $@
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/fstab
