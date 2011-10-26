#
#	Makefile -- Build instructions for Imt/mwi board
#
#	Cloned from vendors/arcturus/uCquicc/Makefile
#	Gerold Boehler <gboehler@cable.vol.at>	
#

#include <linux/config.h>

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin
ELFIMAGE = $(IMAGEDIR)/linux.romfs

DIRS = 

ROMFS_DIRS = dev bin etc

DEVICES = 	tty,c,5,0	console,c,5,1	cua0,c,5,64	cua1,c,5,65 \
		\
		tty0,c,4,0	tty1,c,4,1	ttyS0,c,4,64 \
		\
		ttyp0,c,3,0	ttyp1,c,3,1 \
		\
		ptyp0,c,2,0	ptyp1,c,2,1 \
		\
		flash0,c,6,16 \
		\
		tpu,c,7,0 	portf,c,8,0	porte,c,9,0	lcd,c,10,0 \
		\
		kbd,c,11,0 \
		\
		rom0,b,7,0	rom1,b,7,1	rom2,b,7,2	rom3,b,7,3 \
		rom4,b,7,4	rom5,b,7,5	rom6,b,7,6	rom7,b,7,7 \
		rom8,b,7,8	rom9,b,7,9 

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

	#clean out the /dev directory
	rm $(ROMFSDIR)/dev/* -f \

	for i in $(DEVICES); do \
		touch $(ROMFSDIR)/dev/@$$i; \
	done
	# these permissions are needed for openpty and family to work
	# on non-ptmx ptys
	chmod 620 $(ROMFSDIR)/dev/@[pt]ty[pqrsPQRS][0-9a-f],*
	dirs=$(DIRS) ; for i in $$dirs; do  make -C $$i romfs || exit $? ; done

image:
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	genromfs -v -V "ROMdisk" -f $(ROMFSIMG) -d $(ROMFSDIR)
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.romvec \
			--remove-section=.text --remove-section=.ramvec \
			--remove-section=.bss --remove-section=.eram \
			$(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.data
	$(CROSS_COMPILE)objcopy -O binary --remove-section=.ramvec \
			--remove-section=.bss --remove-section=.data \
			--remove-section=.eram \
			--set-section-flags=.romvec=CONTENTS,ALLOC,LOAD,READONLY,CODE \
			$(ROOTDIR)/$(LINUXDIR)/linux $(IMAGEDIR)/linux.text
	cat $(IMAGEDIR)/linux.text $(IMAGEDIR)/linux.data $(ROMFSIMG) > $(IMAGE)
	cat $(IMAGEDIR)/linux.text $(IMAGEDIR)/linux.data > $(IMAGE)
	BSS=`$(CROSS)objdump --headers $(ROOTDIR)/$(LINUXDIR)/linux | \
	  grep .bss` ; \
	ADDR=`set -- $${BSS} ; echo 0x$${5}` ; \
	$(CROSS)objcopy --add-section=.romfs=$(ROMFSIMG) \
	  --adjust-section-vma=.romfs=$${ADDR} --no-adjust-warnings \
	  --set-section-flags=.romfs=alloc,load,data   \
	  $(ROOTDIR)/$(LINUXDIR)/linux $(ELFIMAGE) 2> /dev/null
	$(CROSS)objcopy -O srec $(ROOTDIR)/$(LINUXDIR)/linux $(ROOTDIR)/images/linux.srec
	$(CROSS)objcopy -O srec $(ROOTDIR)/images/linux.romfs $(ROOTDIR)/images/linux.romfs.srec


