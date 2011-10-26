# Configuration variables
#
# They can also be stored in a file /etc/lilo.defines, e.g.
# -DIGNORECASE -DONE_SHOT
#
# The variables configured in this Makefile are ignored if
# /etc/lilo.defines exists
#
#   ATARAID	  Detect 'dmraid' drivers (linux/drivers/raid/dm.c).
#   AUTOAUTO	  Enable automatic generation of change rules for MS partitions;
#		  issue warning if "CHANGE AUTOMATIC" is assumed
# * BDATA	  Enable real mode gathering of system information for '-T'
#   BEEP	  Beep after displaying "LILO".
#   BOOT_FILE	  Append "BOOT_FILE=<path>" to the kernel command line.
#   BUG_SI_EBDA=n Compensate for BIOS's (notably early Silicon Image S-ATA)
#		  that use the EBDA, but don't properly allocate the space.
#		  (n=1..64) specifies the extra EBDA in kilobytes (default 20).
#   COHERENT	  Make boot loaders (chain.b & mbr.b) compatible with Coherent
#		  by writing the boot device code to the memory copy of the PT
# * DEVMAPPER	  Device Mapper (aka LVM2) support (2.6 kernels only)
# * DSECS=n	  Set the number of Descriptor Sectors (n=1..12).  Each sector
#		  of the descriptor table holds 9..10 descriptors.
# * EVMS	  Enables support for booting from EVMS volumes. Requires a
#		  2.4 or 2.5 kernel patched to EVMS version 1.1.0 or later.
#   HP_TTRC	  Insert 150ms delay for HP TTRC card.  Affects 'second.S'
# * IGNORECASE    Image selection is case-insensitive. Passwords are still
#		  case-sensitive.
#   INITRDLOW	  Always load initial ramdisk images below address 15M,
#		  ignoring any 'large-memory' option in the config file.
# * LVM		  Enables support for booting from LVM partitions.  This will
#		  OOPS if you try to use this and are using a kernel < 2.4.7
#		  that has not been patched to at least LVM 0.9.1beta6.
# * MDPRAID	  Enable automatic marking of volumes of full volume raid
#		  as 'inaccessible.  Add "noraid" keyword to suppress.
#   NO1STDIAG	  Don't show diagnostic on read errors in the first stage
#		  boot. (not recommended)
#   NODRAIN	  Don't drain keyboard buffer after booting.
#   NOINSTDEF     Don't install a new boot sector if INSTALL is not specified.
# * NOKEYBOARD	  Enable the 'nokbdefault' keyword, and test for booting on
#		  a system without a keyboard; alters default descriptor
#		  to be booted.  Enable the 'nokbdisable' keyword also.
#   NOSERIAL	  Don't assemble serial line support in the boot loader.
#   NOVGA	  Don't write to Monochrome or VGA displays.
#   OLD_DIRSTR    Use old locations of config and boot files: (/etc/lilo)
# * ONE_SHOT      Disable the command-line and password timeout if any key is
#		  hit at the boot prompt.
# * PASS160	  Use 160-bit password hash (Secure Hash Standard, see
#		  FIPS PUB 180-1) instead of 64-bit CRC-32 hash
#   READAHEAD	  Enable read-ahead on EDD disks which support the function.
#		  Note:  no BIOS has yet been seen which supports this
#		  EDD revision 1.1 function.
#   READONLY	  Don't write to disk while booting, e.g. don't overwrite the
#		  default command line in the map file after reading it.
# * REISERFS      Compile support for parts of LILO on ReiserFS.
#                 Requires header files for kernel 2.4.0test8 or later.
# * REWRITE_TABLE Enable rewriting the partition table at boot time.
# * SOLO_CHAIN	  Assemble all chain-loader functions into 'chain.b', 
#		  eliminating the need for 'os2_d.b'.
#   SUSPEND=	  Modify 'vmdefault' action if this partition type on C: drive
#		  is marked active; (Dell suspend partition is -DSUSPEND=0x84).
#   USE_TMPDIR	  Create temporary devices in $TMPDIR if set
# * VERSION	  Prints version string at LILO boot prompt.
# * VIRTUAL       Enable 'vmdefault', 'vmdisable', 'vmwarn' keywords; feature
#		  requested by VMware users (new, experimental)
#   XL_SECS=n	  Support for extra large (non-standard) floppies.

ifdef CONFIG_X86
CONFIG=-DBDATA -DDSECS=3 -DEVMS -DIGNORECASE -DLVM -DNOKEYBOARD -DONE_SHOT \
   -DPASS160 -DREISERFS -DREWRITE_TABLE -DSOLO_CHAIN -DVERSION -DVIRTUAL \
   -DMDPRAID
# -DDEVMAPPER
else
CONFIG = -DLCF_IGNORECASE
CONFIG += -DNOSIZELIMIT=1
endif

ifndef HOSTCC
HOSTCC = $(CC)
endif

# do not try to build dos stuff even if bcc is present
NO_DOS_BUILD = yes
   

# set the following if you wish LILO.COM to be installed
DOS_DIR=/dosC/boot
#
# select one of the following to place the man pages in the right place
#MAN_DIR=`if [ -z "$(whereis lilo | grep 'lilo.8')" ]; then \
#	whereis lilo | sed -e "sX.* /usrX/usrX" -e "sX/man8/lilo.8.*XX" ; \
#	elif [ -f /usr/bin/manpath ]; then \
#  manpath | sed "s/:.*//"; else echo /usr/man; fi`
#
MAN_DIR=`if [ -f /usr/bin/manpath ]; then \
	manpath | sed "s/:.*//"; else echo /usr/share/man; fi`
#MAN_DIR=/usr/share/man

# set the compiler optimization level

OPT=-Os

### End of configuration variables
#
#  Do not modify anything below this point
#

SBIN_DIR=/sbin
CFG_DIR=/etc
BOOT_DIR=/boot
USRSBIN_DIR=/usr/sbin
BUILTIN=1

PCONFIG=$(KVER) $(HDM) $(LILO) `( if [ -r $$ROOT/etc/lilo.defines ]; then \
  cat $$ROOT/etc/lilo.defines; else echo $(CONFIG); fi ) | \
  sed 's/-D/-DLCF_/g'`
LILO=-DLILO=0xbb920890
KVER=`if [ -f /usr/include/linux/version.h ]; then echo -DHAS_VERSION_H; fi`
HDM=`if [ -f /usr/include/libdevmapper.h ]; then echo -DHAS_LIBDEVMAPPER_H; fi`
#DEVMAPPER=`if [ -f /usr/include/libdevmapper.h ]; then echo "-ldevmapper"; fi`

TMP=_TmP_


SHELL=/bin/bash
ifndef CC
CC=gcc
endif
CPP=$(CC) -E
AS86=as86 -0 -a
LD86=ld86 -0
NASM=nasm
G=`cat foo1 foo2 | grep version | cut -d " " -f 3`

CFLAGS=$(OPT) -Wall -g $(PCONFIG)
LDFLAGS=#-Xlinker -qmagic
LIBS=$(DEVMAPPER)

OBJS=lilo.o raid.o map.o geometry.o boot.o device.o common.o bsect.o cfg.o \
  partition.o identify.o probe.o shs2.o edit.o temp.o

EDIT=edit.c common.o

LIS=chain.lis disk.lis dparam.lis os2_d.lis first.lis second.lis \
  bootsect.lis third.lis mbr.lis bitmap.lis pseudo.lis mbr2.lis \
  pseudo1.lis loader.lis pseudo3.lis
BFILES=first.b second.b third.b bitmap.b chain.b mbr.b mbr2.b \
  bootsect.b pseudo.b pseudo1.b pseudo3.b
CFILES=boot.c bsect.c cfg.c common.c device.c edit.c geometry.c \
  identify.c lilo.c map.c partition.c probe.c raid.c shs2.c temp.c
HFILES=bdata.h bitmap.h boot.h bsect.h cfg.h common.h config.h device.h \
  edit.h geometry.h identify.h lilo.h loader.h map.h md-int.h partition.h \
  probe.h raid.h shs2.h temp.h version.h vesainfo.h
#BOOTS=boot-text.b boot-menu.b boot-bmp.b chain.b os2_d.b mbr.b mbr2.b

.SUFFIXES:	.img .b .com .S .s

dist: all

romfs:
	$(ROMFSINST) /bin/lilo

#
#  make help
#
help:
	@echo ""
	@echo "Targets:"
	@echo "  make all		# binaries"
	@echo "  make dosexe		# DOS lilo.com utility"
	@echo "  make diagnostic	# standalone diagnostics"
	@echo "  make alles		# all above + static binary"
	@echo "  make docs		# doc/[user,tech].[ps,dvi] docs"
	@echo "  make floppy		# 2 standalone bootable diagnostic floppies"
	@echo ""
	@echo "  make install		# install binaries"
	@echo ""
	@echo "Maintenance:"
	@echo "  make test		# test for all needed utilities (as86, ld86, etc.)"
	@echo "  make tidy		# remove listings & other unnecessary files"
	@echo "  make clean		# remove objects & ready for a fresh 'make all'"
	@echo "  make spotless		# remove editor temps, & all of the above"
	@echo ""

#
# everything needed to run, just short of installation
#
all:	lilo bootsect.b diag1.img # OBSOLETE:  $(BOOTS) edit dparam.com activate
	[ "$(NO_DOS_BUILD)" = "yes" ] || \
	if [ -x /usr/bin/bcc -o -x /usr/local/bin/bcc ]; then \
		make diagnostic; \
		make dosexe; fi

#
# everything above plus the statically linked version
#
alles: all lilo.static

#
# documentation files
#
docs:
	make -C doc all

#
# if you have the 'bcc' compiler, then you can make the diagnostics, too
#
it:	docs alles diagnostic dosexe

#
# test for compilers & utilities
#
test:	test.img
test.img:
	./checkit
	echo Tested >test.img	
#
# make the bootable diagnostic floppies
#
floppy:
	@echo
	@echo Make sure you have 2 blank, formatted, 1.44Mb floppies
	@echo before you proceed from this point.
	@echo "Press <Enter> to continue, <^C> to abort ..."
	@read
	@make floppy1
	@echo Done.
	@echo
	@echo Remove the floppy from the drive.  Label it "\"1.6\""
	@echo "Press <Enter> to continue, <^C> to abort ..."
	@read
	@make floppy2
	@echo Done.
	@echo
	@echo Remove the floppy from the drive.  Label it "\"2.4\""
	@echo

floppy1:	test.img disk.com bootsect.b
	@echo
	@echo Creating Diagnostic Floppy 1.6
	@echo
	@echo Insert a blank, formatted, floppy into drive 0
	@echo "Press <Enter> to continue, <^C> to abort ..."
	@read
	cat bootsect.b disk.com | dd of=/dev/fd0 bs=512

floppy2:	test.img disk.b
	@echo
	@echo Creating Diagnostic Floppy 2.4
	@make -C diagnose check; make -C diagnose floppy

diagnostic:	test.img diag2.img diag3.img
dosexe:		test.img lilo.com

#	if [ -x /usr/bin/bcc -o -x /usr/local/bin/bcc ]; then make diagnostic; \
#	else echo "You don't seem to have the 'bcc' compiler from the 'dev86' package."; \
#		exit 1; fi

manpath:
	echo $(MAN_DIR)

#check-config:
#		$(CPP) check-config.cpp $(PCONFIG) >/dev/null

.c.o:
		$(CC) -c $(CFLAGS) $*.c

.s.o:
		$(AS86) -w -l $*.lis -o $*.o $*.s

.o.img:
		$(LD86) -s -o $*.img $*.o

.img.b:
		dd if=$*.img of=$*.b bs=32 skip=1

activate:	activate.c
		$(CC) -Wall -s -O -o activate activate.c $(LDFLAGS)

edit:		$(EDIT)
		$(CC) -Wall -s -O -DSTANDALONE -o edit $(EDIT) $(LDFLAGS)

loader.i:	mkloader first.b second.b third.b bitmap.b mbr.b \
			chain.b os2_d.b mbr2.b
		./mkloader >loader.i

#loader.o:	loader.s first.b second.b third.b bitmap.b mbr.b \
#			chain.b os2_d.b mbr2.b
#		$(NASM) -f elf -o loader.o -l loader.lis  loader.s

#loader.s:	loader.S
#		$(CPP) -traditional $(PCONFIG) -o loader.s  loader.S

disk.com:	disk.b
		cp disk.b disk.com

disk.s:		disk.S read.S bdata.h biosdata.S lilo.h Makefile
		$(CPP) -traditional $(PCONFIG) -o disk.s  disk.S

mbr.s:		mbr.S lilo.h Makefile
		$(CPP) -traditional $(PCONFIG) -DMBR=0xafbbe760 \
			-o mbr.s  mbr.S

mbr.b:		mbr.img
		dd if=$*.img of=$*.b bs=32 skip=49

mbr2.s:		mbr.S lilo.h Makefile
		$(CPP) -traditional $(PCONFIG) -DMBX=0x93c00848 \
			-o mbr2.s  mbr.S

mbr2.b:		mbr2.img
		dd if=$*.img of=$*.b bs=32 skip=49

bootsect.s:	bootsect.S disk.b
		$(CPP) -traditional $(PCONFIG) \
			-DSIZEDISKB=`wc -c <disk.b | sed "s/ //g"` \
			-o bootsect.s  bootsect.S

pseudo.s:	bootsect.S pseudo.S diagnose/test4.com
		cat bootsect.S pseudo.S >$(TMP).S
		$(CPP) -traditional $(PCONFIG) \
			-DSIZEKRNL=`wc -c <diagnose/test4.com | sed "s/ //g"` \
			-DSIZEDISKB=512 -o pseudo.s $(TMP).S
		rm -f $(TMP).S

pseudo1.s:	bootsect.S pseudo.S disk.com
		cat bootsect.S pseudo.S >$(TMP).S
		$(CPP) -traditional $(PCONFIG) \
			-DSIZEKRNL=`wc -c <disk.com | sed "s/ //g"` \
			-DSIZEDISKB=512 -o pseudo1.s $(TMP).S
		rm -f $(TMP).S

pseudo3.s:	bootsect.S pseudo.S diagnose/test5.com
		cat bootsect.S pseudo.S >$(TMP).S
		$(CPP) -traditional $(PCONFIG) \
			-DSIZEKRNL=`wc -c <diagnose/test5.com | sed "s/ //g"` \
			-DSIZEDISKB=512 -o pseudo3.s $(TMP).S
		rm -f $(TMP).S

pseudo.b:	pseudo.s
pseudo1.b:	pseudo1.s
pseudo3.b:	pseudo3.s

diagnose/test4.com: 	diagnose/test4.c
	make -C diagnose all

diagnose/test5.com:	diagnose/test5.c
	make -C diagnose all

diag1.img:	disk.com pseudo1.b
	cat pseudo1.b disk.com >diag1.img

diag2.img:	diagnose/test4.com pseudo.b
	cat pseudo.b diagnose/test4.com >diag2.img

diag3.img:	diagnose/test5.com pseudo3.b
	cat pseudo3.b diagnose/test5.com >diag3.img

dos/lilo.com:
	make -C dos -e CFLAGS="$(PCONFIG)" lilo.com

lilo.com:	dos/lilo.com
	cp -uf $< $@


flags.i:	test.img Makefile version $(CFILES) $(HFILES)
	echo "#define CFLAGS \"" $(CFLAGS) "\"" >flags.i
	tail -$$((`wc -l <Makefile`-`sed /\#\#\#/q <Makefile | wc -l`)) \
	  <Makefile | grep -v "0x" >$(TMP)
	for i in $(CFILES) $(HFILES) ; do cat $$i >>$(TMP) ; done
	echo "#define CSOURCE " `./version $(TMP)` >>flags.i
	rm -f $(TMP)


dparam.com:	dparam.img
		dd if=dparam.img of=dparam.com bs=288 skip=1

dparam.s:	dparam.S
		cp -p dparam.S dparam.s

lilo:		$(OBJS)
		$(CC) -o lilo $(LDFLAGS) $(OBJS) $(LIBS)

lilo.static:	$(OBJS)
		$(CC) -o lilo.static -static $(LDFLAGS) $(OBJS) $(LIBS)

boot-text.b:	first.b second.b
		(dd if=first.b bs=512 conv=sync; dd if=second.b) >boot-text.b

boot-menu.b:	first.b third.b
		(dd if=first.b bs=512 conv=sync; dd if=third.b) >boot-menu.b

boot-bmp.b:	first.b bitmap.b
		(dd if=first.b bs=512 conv=sync; dd if=bitmap.b) >boot-bmp.b

common.s:	common.h
		$(CPP) -C -traditional -DLILO_ASM -o common.s common.h

bitmap.o: bitmap.s common.s
third.o: third.s common.s
second.o: second.s common.s
first.o: first.s common.s
chain.o: chain.s common.s

first.s:	first.S lilo.h version.h Makefile
		$(CPP) $(PCONFIG) -DFIRST=0x62177489 -o first.s first.S

second.s:	second.S read.S volume.S mapper.S biosdata.S shs3.S bdata.h lilo.h version.h \
			graph.S menu.S strlen.S bitmap.S crt.S display4.S Makefile
		$(CPP) $(PCONFIG) -DTEXT=0x9dd476ec second.S -o second.s

third.s:	second.S read.S volume.S mapper.S biosdata.S shs3.S bdata.h lilo.h version.h \
			graph.S menu.S strlen.S bitmap.S crt.S display4.S Makefile
		$(CPP) $(PCONFIG) -DMENU=0x2012a4a7 second.S -o third.s

bitmap.s:	second.S read.S volume.S mapper.S biosdata.S shs3.S bdata.h lilo.h version.h \
			graph.S menu.S strlen.S bitmap.S crt.S display4.S Makefile
		$(CPP) $(PCONFIG) -DBITMAP=0x2ece2fbe second.S -o bitmap.s

chain.s:	chain.S lilo.h version.h first.b Makefile
		$(CPP) $(PCONFIG) -DCHAIN=0x536a7646 chain.S -o chain.s

os2_d.s:	chain.S lilo.h version.h first.b Makefile
		$(CPP) $(PCONFIG) chain.S -DDOS_D -o os2_d.s

#dos_d.s:	chain.S lilo.h version.h first.b
#		$(CPP) $(PCONFIG) chain.S -DDOS_D -o dos_d.s

#dump.s:		dump.S lilo.h version.h first.b
#		$(CPP) $(PCONFIG) `./lilo -X` dump.S -DDOS_D -o dump.s

xxx.s:		chain.S lilo.h Makefile
		$(CPP) chain.S -DXXX -o xxx.s

$(OBJS):	Makefile

#
# shorthand, if one knows that one has the 'bcc' compiler
#
ins:	diag install

#
#  normal install, but doesn't make the diagnostic binaries
#
install:  all
	mkdir -p $$ROOT$(SBIN_DIR) $$ROOT$(CFG_DIR) $$ROOT$(BOOT_DIR) \
	  $$ROOT$(USRSBIN_DIR) $$ROOT$(MAN_DIR)/man5 $$ROOT$(MAN_DIR)/man8
	if [ -f diag1.img ]; then \
	  cp -f diag1.img $$ROOT$(BOOT_DIR); fi
	if [ -f diag2.img ]; then \
	  cp -f diag2.img $$ROOT$(BOOT_DIR); fi
	if [ ! -L $$ROOT$(BOOT_DIR)/boot.b -a -f $$ROOT$(BOOT_DIR)/boot.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/boot.b $$ROOT$(BOOT_DIR)/boot.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/boot-bmp.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/boot-bmp.b $$ROOT$(BOOT_DIR)/boot-bmp.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/boot-menu.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/boot-menu.b $$ROOT$(BOOT_DIR)/boot-menu.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/boot-text.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/boot-text.b $$ROOT$(BOOT_DIR)/boot-text.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/chain.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/chain.b $$ROOT$(BOOT_DIR)/chain.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/os2_d.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/os2_d.b $$ROOT$(BOOT_DIR)/os2_d.old; fi
	if [ -f $$ROOT$(BOOT_DIR)/mbr.b ]; then \
	  mv $$ROOT$(BOOT_DIR)/mbr.b $$ROOT$(BOOT_DIR)/mbr.old; fi
	if [ -f os2_d.b  -a  $(BUILTIN) = 0 ]; then \
	  cp os2_d.b $$ROOT$(BOOT_DIR); fi
	if [ $(BUILTIN) = 0 ]; then \
	  cp boot-text.b boot-menu.b boot-bmp.b chain.b mbr.b $$ROOT$(BOOT_DIR); fi
	if [ ! -L $$ROOT$(BOOT_DIR)/boot.b  -a  $(BUILTIN) = 0 ]; then \
	  ln -s boot-menu.b $$ROOT$(BOOT_DIR)/boot.b; fi
	if [ $(BUILTIN) = 1 ]; then \
	  rm -f $$ROOT$(BOOT_DIR)/boot.b; fi
	cp mkrescue $$ROOT$(SBIN_DIR)
	cp lilo $$ROOT$(SBIN_DIR)
	strip $$ROOT$(SBIN_DIR)/lilo
	cp keytab-lilo.pl $$ROOT$(USRSBIN_DIR)
	cp manPages/lilo.8 $$ROOT$(MAN_DIR)/man8
	cp manPages/mkrescue.8 $$ROOT$(MAN_DIR)/man8
	cp manPages/lilo.conf.5 $$ROOT$(MAN_DIR)/man5
	if [ -d $$ROOT$(DOS_DIR) -a -f lilo.com ]; then \
	  cp lilo.com $$ROOT$(DOS_DIR); fi
	@if [ -e $$ROOT/etc/lilo/install ]; then echo; \
	  echo -n "$$ROOT/etc/lilo/install is obsolete. LILO is now ";\
	  echo "re-installed "; \
	  echo "by just invoking $(SBIN_DIR)/lilo"; echo; fi
	@echo "$(SBIN_DIR)/lilo must now be run to complete the update."

dep:
		sed '/\#\#\# Dependencies/q' <Makefile >tmp_make
		$(CPP) $(CFLAGS) -MM *.c >>tmp_make
		mv tmp_make Makefile

version:	common.c lilo.h common.h
		$(HOSTCC) $(CFLAGS) -DSHS_MAIN -o version common.c

mkloader:	temp.c
		$(HOSTCC) $(CFLAGS) -DLILO_BINARY -o mkloader temp.c

tidy:
		rm -f core $(LIS) *.shs *.crc $(TMP)*
		rm -rf sbin boot usr
		make -C diagnose tidy
		make -C dos tidy
		make -C doc tidy
		if [ -x lilo ]; then strip lilo; fi
		if [ -x lilo.static ]; then strip lilo.static; fi

clean:		tidy
		rm -f *.o *.s *.i *.img *.b tmp_make version
		rm -f lilo lilo.static activate edit mkloader
		make -C diagnose clean
		make -C dos clean

spotless:	clean
		rm -f *~ */*~ *.b *.com lilo*tar.gz
		make -C diagnose spotless
		make -C dos spotless
		make -C doc clean

### Dependencies
activate.o: activate.c
boot.o: boot.c config.h lilo.h version.h common.h geometry.h device.h \
  cfg.h map.h partition.h boot.h loader.h
bsect.o: bsect.c config.h lilo.h version.h common.h raid.h cfg.h device.h \
  geometry.h map.h temp.h partition.h boot.h bsect.h bitmap.h probe.h \
  loader.h edit.h shs2.h
cfg.o: cfg.c lilo.h version.h common.h temp.h cfg.h
common.o: common.c lilo.h version.h common.h
device.o: device.c config.h lilo.h version.h common.h temp.h device.h \
  geometry.h partition.h cfg.h probe.h md-int.h
edit.o: edit.c config.h lilo.h version.h common.h cfg.h temp.h bsect.h \
  bitmap.h edit.h
geometry.o: geometry.c config.h lilo.h version.h common.h device.h raid.h \
  geometry.h cfg.h md-int.h probe.h
identify.o: identify.c lilo.h version.h common.h cfg.h
lilo.o: lilo.c config.h lilo.h version.h common.h cfg.h raid.h boot.h \
  device.h flags.i geometry.h map.h bsect.h identify.h partition.h \
  probe.h temp.h loader.h md-int.h edit.h bitmap.h
map.o: map.c lilo.h version.h common.h geometry.h map.h
partition.o: partition.c config.h lilo.h version.h common.h cfg.h \
  device.h geometry.h partition.h boot.h loader.h
probe.o: probe.c lilo.h version.h common.h device.h geometry.h \
  partition.h bsect.h bdata.h probe.h
raid.o: raid.c config.h lilo.h version.h common.h raid.h boot.h device.h \
  geometry.h bsect.h cfg.h partition.h md-int.h
shs2.o: shs2.c lilo.h version.h shs2.h
temp.o: temp.c lilo.h version.h common.h temp.h loader.i
