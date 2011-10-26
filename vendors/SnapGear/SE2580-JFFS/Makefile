#
#	Makefile -- Build instructions for SnapGear/SE2580-JFFS
#

include $(LINUX_CONFIG)
include $(CONFIG_CONFIG)
include $(ARCH_CONFIG)

all clean image:
	$(MAKE) -C ../SE2580 $@

romfs:
	$(MAKE) -C ../SE2580 $@
	$(ROMFSINST) /etc/rc
	$(ROMFSINST) /etc/fstab
