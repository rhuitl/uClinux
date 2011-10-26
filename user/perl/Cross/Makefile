## Toplevel Makefile for cross-compilation of perl
#
## $Id: Makefile,v 1.7 2004/01/12 15:41:02 red Exp red $

export TOPDIR=${shell pwd}
include $(TOPDIR)/config
export SYS=$(ARCH)-linux

all:
	@echo Please read the README file before doing anything else.

gen_patch:
	diff -Bbur ../Makefile.SH Makefile.SH > Makefile.SH.patch
	diff -Bbur ../installperl installperl > installperl.patch

patch:
	cd .. ; if [ ! -e ./CROSS_PATCHED ] ; then \
		patch -p1 < Cross/Makefile.SH.patch; \
		patch -p1 < Cross/installperl.patch ; mv installperl installperl-patched; \
		sed -e 's/XXSTRIPXX/$(SYS)/' installperl-patched > installperl; \
		touch CROSS_PATCHED ; fi

dry_patch:
	cd .. ;	patch --dry-run -p1 < Cross/Makefile.SH.patch; \
		patch --dry-run -p1 < Cross/installperl.patch; \

perl:
	@echo Perl cross-build directory is $(TOPDIR)
	@echo Target arch is $(SYS)
	@echo toolchain: $(CC), $(CXX), $(LD), $(STRIP), $(AR), $(RANLIB)
	@echo Optimizations: $(FULL_OPTIMIZATION)

	$(TOPDIR)/generate_config_sh config.cross > $(TOPDIR)/../config.sh
	cd $(TOPDIR)/.. ; ./Configure -S
	cd $(TOPDIR)/.. ; make depend
	cd $(TOPDIR)/.. ; make
	#cd $(TOPDIR)/.. ; ./Configure -S ; make depend ; make ; make more
	#cd $(TOPDIR)/.. ; mkdir -p fake_config_library ; cp lib/Config.pm fake_config_library
	#cd $(TOPDIR)/.. ; $(MAKE) more2 "PERLRUN=/usr/bin/perl -I$(TOPDIR)/../fake_config_library -MConfig"
	#cd $(TOPDIR)/.. ; $(MAKE) more3 "PERLRUN=/usr/bin/perl -I$(TOPDIR)/../fake_config_library -MConfig"
	#cd $(TOPDIR)/.. ; $(MAKE) more4 "PERLRUN=/usr/bin/perl -I$(TOPDIR)/../fake_config_library -MConfig"
	#cd $(TOPDIR)/.. ; rm -rf install_me_here
	#cd $(TOPDIR)/.. ; make install-strip
	#cd $(TOPDIR)/.. ; sh -x Cross/warp


