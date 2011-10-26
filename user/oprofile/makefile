CONFOPTS = --prefix=/usr --with-kernel-support
CXXFLAGS += -I$(STL_INCDIR)
LDFLAGS += -L$(STL_LIBDIR)

FILE_IMAGE = $(ROOTDIR)/$(LINUXDIR)/vmlinux 



all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/daemon/oprofiled /usr/bin/oprofiled
	$(ROMFSINST) build/utils/ophelp /usr/bin/ophelp
	$(ROMFSINST) -p 755 utils/opcontrol /usr/bin/opcontrol
	$(ROMFSINST) build/pp/opreport /usr/bin/opreport
	$(ROMFSINST) -d events/arm/xscale2/events /usr/share/oprofile/arm/xscale2/events
	$(ROMFSINST) -d events/arm/xscale2/unit_masks /usr/share/oprofile/arm/xscale2/unit_masks
	$(ROMFSINST) -S $(FILE_IMAGE) /vmlinux
	range_info=`objdump -h $(FILE_IMAGE) 2>/dev/null | grep " .text "`; \
	tmp1=`echo $$range_info | awk '{print $$4}'`; \
	tmp_length=`echo $$range_info | awk  '{print $$3}'`; \
	tmp2=`objdump -h $(FILE_IMAGE) --adjust-vma=0x$$tmp_length 2>/dev/null | grep " .text " | awk  '{print $$4}'`; \
	$(ROMFSINST) -a "opcontrol --vmlinux=/vmlinux --kernel-range=`echo $$tmp1`,`echo $$tmp2`" /etc/rc


