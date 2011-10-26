# FreeS/WAN master makefile
# Copyright (C) 1998-2002  Henry Spencer.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.163.2.5 2002/04/12 04:08:31 mcr Exp $



include Makefile.inc
include Makefile.ver



# kernel details
# what variant of our patches should we use, and where is it
# don't take KERNELREL too seriously; "2.3" does include 2.4
KERNELREL=$(shell { test -f $(FILIN24) && echo 2.3; } || \
		{ test -d $(DIRIN22) && echo 2.2; } )
PATCHES=klips/patches$(KERNELREL)
# where KLIPS goes in the kernel
# note, some of the patches know the last part of this path
KERNELKLIPS=$(KERNELSRC)/net/ipsec

# directories visited install, programs, check, etc.
SUBDIRS=libdes lib pluto klips utils testing

# declaration for make's benefit
.PHONY:	def insert klink patches _patches _patches2.2 _patches2.3 \
	klipsdefaults programs install clean distclean \
	ogo oldgo menugo xgo \
	omod oldmod menumod xmod \
	orpm oldrpm menurpm xrpm rpm\
	pcf ocf mcf xcf \
	precheck verset confcheck kernel module kinstall minstall \
	rpminstall rpmkinstall rpms backup unpatch uinstall_freeswan \
	snapready relready ready buildready devready uml check

# dummy default rule
def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# everything that's necessary to put Klips into the kernel
insert:	patches klink klipsdefaults

# create KERNELKLIPS and populate it with symlinks to the sources
klink:
	rm -rf $(KERNELKLIPS)
	mkdir -p $(KERNELKLIPS)/libdes/asm
	mkdir -p $(KERNELKLIPS)/libfreeswan
	mkdir -p $(KERNELKLIPS)/zlib
	$(KLIPSLINK) `pwd`/klips/net/ipsec/Makefile $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/Makefile.inc $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/Makefile.ver $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/klips/net/ipsec/Config.in $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/klips/net/ipsec/defconfig $(KERNELKLIPS)
	$(KLIPSLINK) `pwd`/klips/net/ipsec/*.[ch] $(KERNELKLIPS)
	mkdir $(KERNELKLIPS)/alg
	$(KLIPSLINK) `pwd`/klips/net/ipsec/alg/* $(KERNELKLIPS)/alg
	$(KLIPSLINK) `pwd`/libcrypto $(KERNELKLIPS)/libcrypto
	$(KLIPSLINK) `pwd`/lib/Makefile.kernel $(KERNELKLIPS)/libfreeswan/Makefile
	$(KLIPSLINK) `pwd`/lib/*.[ch] $(KERNELKLIPS)/libfreeswan
	$(KLIPSLINK) `pwd`/libdes/Makefile $(KERNELKLIPS)/libdes
	$(KLIPSLINK) `pwd`/libdes/*.[ch] $(KERNELKLIPS)/libdes
	$(KLIPSLINK) `pwd`/libdes/asm/*.pl $(KERNELKLIPS)/libdes/asm
	$(KLIPSLINK) `pwd`/libdes/asm/perlasm $(KERNELKLIPS)/libdes/asm
	$(KLIPSLINK) `pwd`/zlib/Makefile $(KERNELKLIPS)/zlib
	$(KLIPSLINK) `pwd`/zlib/*.[chS] $(KERNELKLIPS)/zlib

# patch kernel
PATCHER=utils/patcher
patches:
	echo "===============" >>out.kpatch
	echo "`date` `cd $(KERNELSRC) ; pwd`" >>out.kpatch
	$(MAKE) _patches$(KERNELREL) >>out.kpatch

# Linux-2.0.x version
_patches:
	@$(PATCHER) -v $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES)/Documentation.Configure.help
	@$(PATCHER) -v $(KERNELSRC) include/linux/in.h \
		'IPPROTO_ESP' $(PATCHES)/include.linux.in.h
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
	@$(PATCHER) -v $(KERNELSRC) net/netsyms.c \
		'ip_fragment' $(PATCHES)/net.netsyms.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h \
		'PF_KEY' $(PATCHES)/include.linux.socket.h
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.2.x version
PATCHES24=klips/patches2.3
_patches2.2:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES)/Doc.Configure.help
	@$(PATCHER) -v $(KERNELSRC) include/linux/in.h \
		'IPPROTO_ESP' $(PATCHES)/include.linux.in.h
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES24)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
	@$(PATCHER) -v $(KERNELSRC) net/netsyms.c \
		'neigh_compat_output' $(PATCHES)/net.netsyms.c.1 \
		'inet_addr_type' $(PATCHES)/net.netsyms.c.2
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.udp.c
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_IPSEC' $(PATCHES)/include.net.sock.h
#	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h \
#		'define.AF_KEY' $(PATCHES)/include.linux.socket.h
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/socket.h
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# Linux-2.4.0 version
PATCHES22=klips/patches2.2
_patches2.3:
	@$(PATCHER) -v -c $(KERNELSRC) Documentation/Configure.help \
		'CONFIG_IPSEC' $(PATCHES22)/Doc.Configure.help
	@$(PATCHER) -v $(KERNELSRC) net/Config.in \
		'CONFIG_IPSEC' $(PATCHES)/net.Config.in
	@$(PATCHER) -v $(KERNELSRC) net/Makefile \
		'CONFIG_IPSEC' $(PATCHES)/net.Makefile
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/af_inet.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.af_inet.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/udp.c \
		'CONFIG_IPSEC' $(PATCHES)/net.ipv4.udp.c
	@$(PATCHER) -v $(KERNELSRC) include/net/sock.h \
		'CONFIG_IPSEC' $(PATCHES)/include.net.sock.h
# Removed patches, will unpatch automatically.
	@$(PATCHER) -v $(KERNELSRC) include/linux/proc_fs.h
	@$(PATCHER) -v $(KERNELSRC) net/core/dev.c
	@$(PATCHER) -v $(KERNELSRC) net/ipv4/protocol.c
	@$(PATCHER) -v $(KERNELSRC) drivers/net/Space.c
	@$(PATCHER) -v $(KERNELSRC) include/linux/netlink.h
	@$(PATCHER) -v $(KERNELSRC) net/netlink/af_netlink.c
	@$(PATCHER) -v $(KERNELSRC) net/netlink/netlink_dev.c
	@$(PATCHER) -v $(KERNELSRC) drivers/isdn/isdn_net.c

# supply kernel-configuration defaults
ifeq ($(ARCH),)
ARCH := $(shell uname -m | sed -e s/i.86/i386/ -e s/sun4u/sparc64/ -e s/arm.*/arm/ -e s/sa110/arm/)
endif
klipsdefaults:
	@KERNELDEFCONFIG=$(KERNELSRC)/arch/$(ARCH)/defconfig ; \
	KERNELCONFIG=$(KCFILE) ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELDEFCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELDEFCONFIG $$KERNELDEFCONFIG.orig ; \
		chmod u+w $$KERNELDEFCONFIG ; \
		cat $$KERNELDEFCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELDEFCONFIG.tmp ; \
		rm -f $$KERNELDEFCONFIG ; \
		cp -a $$KERNELDEFCONFIG.tmp $$KERNELDEFCONFIG ; \
		rm -f $$KERNELDEFCONFIG.tmp ; \
	fi ; \
	if ! egrep -q 'CONFIG_IPSEC' $$KERNELCONFIG ; \
	then \
		set -x ; \
		cp -a $$KERNELCONFIG $$KERNELCONFIG.orig ; \
		chmod u+w $$KERNELCONFIG ; \
		cat $$KERNELCONFIG $(KERNELKLIPS)/defconfig \
			>$$KERNELCONFIG.tmp ; \
		rm -f $$KERNELCONFIG ; \
		cp -a $$KERNELCONFIG.tmp $$KERNELCONFIG ; \
		rm -f $$KERNELCONFIG.tmp ; \
	fi



# programs

programs:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} programs); done

install:
	mkdir -p $(PRIVDIR) $(PUBDIR)
	mkdir -p -m 755 $(CONFDIR)/ipsec.d
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/cacerts
	mkdir -p -m 755 $(CONFDIR)/ipsec.d/crls
	mkdir -p -m 700 $(CONFDIR)/ipsec.d/private
	for m in $(MANPLACES) ; do mkdir -p $(MANTREE)/$$m || exit 1 ; done
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} install); done

clean:
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} clean); done
	rm -rf $(RPMTMPDIR) $(RPMDEST)
	rm -f out.*build out.*install	# but leave out.kpatch
	rm -f rpm.spec

distclean:	clean
	rm -f out.kpatch



# proxies for major kernel make operations

# do-everything entries
PRE=precheck verset insert
POST=confcheck programs install kernel
MPOST=confcheck programs install module
RPOST=confcheck programs rpminstall module rpmkinstall rpms
ogo:	$(PRE) pcf $(POST)
oldgo:	$(PRE) ocf $(POST)
menugo:	$(PRE) mcf $(POST)
xgo:	$(PRE) xcf $(POST)
omod:	$(PRE) pcf $(MPOST)
oldmod:	$(PRE) ocf $(MPOST)
menumod:	$(PRE) mcf $(MPOST)
xmod:	$(PRE) xcf $(MPOST) 
orpm:	$(PRE) pcf $(RPOST) 
modrpm:	$(PRE) ocf confcheck module rpmkmodinstall 
oldrpm:	$(PRE) ocf $(RPOST) 
menurpm:	$(PRE) mcf $(RPOST) 
xrpm:	$(PRE) xcf $(RPOST) 

# preliminaries
precheck:
	@if test ! -d $(KERNELSRC) -a ! -L $(KERNELSRC) ; \
	then \
		echo '*** cannot find directory "$(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if ! cd $(KERNELSRC) ; \
	then \
		echo '*** cannot "cd $(KERNELSRC)"!!' ; \
		echo '*** may be necessary to add symlink to kernel source' ; \
		exit 1 ; \
	fi
	@if test ! -f $(KCFILE) ; \
	then \
		echo '*** cannot find "$(KCFILE)"!!' ; \
		echo '*** perhaps kernel has never been configured?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi
	@if test ! -f $(VERFILE) ; \
	then \
		echo '*** cannot find "$(VERFILE)"!!' ; \
		echo '*** perhaps kernel has never been compiled?' ; \
		echo '*** please do that first; the results are necessary.' ; \
		exit 1 ; \
	fi

# set version code if this is a fresh CVS checkout
verset: 
	if test -f cvs.datemark ; \
	then \
		sed "/^IPSECVERSION=xxx/s/xxx/` \
			date -r cvs.datemark +cvs%Y%b%d_%H:%M:%S \
		`/" Makefile.ver >Makefile.ver$$$$ && \
		mv Makefile.ver$$$$ Makefile.ver ; \
		rm -f cvs.datemark ; \
	fi

# configuring (exit statuses disregarded, something fishy here sometimes)
xcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) xconfig
mcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) menuconfig
pcf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) config

ocf:
	-cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) oldconfig dep </dev/null >/dev/null

rpm:
	mkdir -p ${RPMKERNDIR}
	rm -rf $(RPMTMPDIR)
	if [ ! -d ${RH_KERNELSRC}/configs ]; then echo "Please fix RH_KERNELSRC in Makefile.inc"; exit 1; fi
	cd ${RPMKERNDIR} && lndir ${RH_KERNELSRC} .
	# this is a fixup for problems with having include/asm exist, and
	# being unable to replace it during the build
	rm -f ${RPMKERNDIR}/include/asm
	for cfg in ${RPMKERNDIR}/configs/*.config; \
	do \
		cfgshort=`basename $$cfg .config | sed -e 's/kernel-[^-]*-\(.*\)/\1/'`; \
		cp $$cfg ${RPMKERNDIR}/.config; \
		echo ============= Building for config file $$cfgshort =========== ; \
		make KERNELSRC=${RPMKERNDIR} KERNMAKEOPTS="EXTRAVERSION=-$$cfgshort" CFGSHORT=$$cfgshort modclean ocf; \
		make KERNELSRC=${RPMKERNDIR} KERNMAKEOPTS="EXTRAVERSION=-$$cfgshort" CFGSHORT=$$cfgshort modrpm || exit 1; \
	done; 
	make KERNELSRC=${RPMKERNDIR} programs 
	make KERNELSRC=${RPMKERNDIR} rpminstall 
	make KERNELSRC=${RPMKERNDIR} rpms

confcheck:
	@if test ! -f $(KCFILE) ; \
	then echo '*** no kernel configuration file written!!' ; exit 1 ; \
	fi
	@if ! egrep -q '^CONFIG_IPSEC=[my]' $(KCFILE) ; \
	then echo '*** IPsec not in kernel config ($(KCFILE))!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_IPSEC[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_IPSEC_MODULE[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec in kernel config ($(KCFILE)),' ; \
		echo '***	but not in config header file ($(ACFILE))!!' ; \
		exit 1 ; \
	fi
	@if egrep -q '^CONFIG_IPSEC=m' $(KCFILE) && \
		! egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then echo '*** IPsec configured as module in kernel with no module support!!' ; exit 1 ; \
	fi
	@if ! egrep -q 'CONFIG_IPSEC_AH[ 	]+1' $(ACFILE) && \
		! egrep -q 'CONFIG_IPSEC_ESP[ 	]+1' $(ACFILE) ; \
	then echo '*** IPsec configuration must include AH or ESP!!' ; exit 1 ; \
	fi

# kernel building, with error checks
kernel:
	rm -f out.kbuild out.kinstall
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) $(KERNDEP) $(KERNCLEAN) $(KERNEL) ) 2>&1 | tee out.kbuild
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules 2>&1 ) | tee -a out.kbuild ; \
	fi
	utils/errcheck out.kbuild

# module-only building, with error checks
module:
	rm -f out.kbuild out.kinstall
	egrep -q '^CONFIG_MODULES=y' $(KCFILE)
	egrep -q '^CONFIG_IPSEC=m' $(KCFILE)
	( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) SUBDIRS=net/ipsec modules 2>&1 ) | tee out.kbuild
	utils/errcheck out.kbuild

modclean:
	cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) SUBDIRS=net/ipsec clean 

# kernel install, with error checks
kinstall:
	rm -f out.kinstall
	( cd $(KERNELSRC) ; $(MAKE) $(KERNMAKEOPTS) install ) 2>&1 | tee out.kinstall
	@if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then set -x ; \
		( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) modules_install 2>&1 ) | tee -a out.kinstall ; \
	fi
	utils/errcheck out.kinstall

# module-only install, with error checks
minstall:
	rm -f out.kinstall
	egrep -q '^CONFIG_MODULES=y' $(KCFILE)
	egrep -q '^CONFIG_IPSEC=m' $(KCFILE)
	( cd $(KERNELSRC) ; \
		$(MAKE) $(KERNMAKEOPTS) SUBDIRS=net/ipsec modules_install 2>&1 ) | tee out.kinstall
	utils/errcheck out.kinstall

# RPM-build userland install in temporary directory
rpminstall:
	mkdir -p $(RPMTMPDIR)
	$(MAKE) install DESTDIR=$(RPMTMPDIR)

# RPM-build kinstall in temporary directory
# Some of this is not really right for non-x86 systems, but alas, there's no
# override like INSTALL_MOD_PATH for kernel itself, so must do it by hand.
RPMBOOT=$(RPMTMPDIR)/boot
rpmkinstall:
	mkdir -p $(RPMBOOT)
	( KV=`utils/kernelversion $(KERNELSRC)/Makefile` ; \
		cd $(KERNELSRC) ; \
		if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
		then $(MAKE) $(KERNMAKEOPTS) INSTALL_MOD_PATH=$(RPMTMPDIR) \
			SUBDIRS=net/ipsec modules_install ; \
		else \
		  cp arch/$(ARCH)/boot/$(KERNEL) $(RPMBOOT)/vmlinuz-$$KV ; \
		  cp System.map $(RPMBOOT)/System.map-$$KV ; \
		fi; \
	) 2>&1 | tee out.rpmkinstall
	utils/errcheck out.rpmkinstall

rpmkmodinstall:
	mkdir -p $(RPMBOOT)
	( KV=`utils/kernelversion $(KERNELSRC)/Makefile` ; \
		cd $(KERNELSRC) ; \
		mkdir -p ${RPMTMPDIR}/lib/modules/ipsec; \
		cp net/ipsec/ipsec.o ${RPMTMPDIR}/lib/modules/ipsec/ipsec.o-${CFGSHORT}; \
		goo="`nm -g net/ipsec/ipsec.o | sed -n '/ netif_rx_R/s/.*_R//p'`"; \
		cp net/ipsec/ipsec.o ${RPMTMPDIR}/lib/modules/ipsec/$$goo; \
	) 2>&1 | tee out.rpmkinstall
	utils/errcheck out.rpmkinstall

# build RPMs
rpms:	rpm.spec $(RPMTMPDIR)
	rm -rf $(RPMDEST)
	mkdir $(RPMDEST)
	cd $(RPMDEST) ; mkdir SRPMS BUILD RPMS SPECS SOURCES
	cd $(RPMDEST)/RPMS ; mkdir $(ARCH) noarch
	rpm -bb --define "buildroot $(RPMTMPDIR)" \
		--define "_topdir $(RPMDEST)" rpm.spec
	# that has, incidentally, gotten rid of $(RPMTMPDIR)

# build spec file for building RPMs
rpm.spec:	rpm.in $(KERNELSRC)/Makefile $(KCFILE)
	KV=`utils/kernelversion $(KERNELSRC)/Makefile | sed -e 's/-/_/'` ; \
	if egrep -q '^CONFIG_MODULES=y' $(KCFILE) ; \
	then KMO='/^@km */s///' ; \
	else KMO='/^@km */d' ; \
	fi ; \
	if egrep -q '^CONFIG_IPSEC=m' $(KCFILE) ; \
	then FMO='/^@fm */s///' ; \
	else FMO='/^@fm */d' ; \
	fi ; \
	sed -e "/@KERNELVERSION@/s;;$$KV;" \
		-e '/@IPSECVERSION@/s;;$(IPSECVERSION);' \
		-e "$$KMO" \
		-e "$$FMO" \
		-e '/@PUBDIR@/s;;$(PUBDIR);' \
		-e '/@FINALBINDIR@/s;;$(FINALBINDIR);' \
		-e '/@MANTREE@/s;;$(MANTREE);' rpm.in >$@

# backup of (almost) everything an install touches
TARNAME=$(shell date | awk '{print "backup-" $$6 "-" $$2 "-" $$3 ".tar.gz"}')
THEM=$(PUBDIR)/ipsec $(PRIVDIR)/* $(MANTREE)/*/ipsec* \
	$(CONFDIR)/ipsec.conf $(CONFDIR)/ipsec.secrets \
	$(RCDIR)/ipsec $(KCFILE) \
	$(KERNELSRC)/arch/$(ARCH)/defconfig \
	$(RCDIR)/../rc[0-6].d/[KS]??ipsec
backup:
	tar -cz --ignore-failed-read -f $(TARNAME) $(THEM)
	chmod -w $(TARNAME)

# take all the patches out of the kernel
# (Note, a couple of files are modified by non-patch means; they are
# included in "make backup".)
unpatch:
	for f in `find $(KERNELSRC)/. -name '*.preipsec' -print` ; \
	do \
		echo "restoring $$f:" ; \
		dir=`dirname $$f` ; \
		core=`basename $$f .preipsec` ; \
		cd $$dir ; \
		mv -f $$core.preipsec $$core ; \
		rm -f $$core.wipsec $$core.ipsecmd5 ; \
	done

# uninstall, as much as possible
uninstall_freeswan:
	rm -f $(RCDIR)/ipsec $(PUBDIR)/ipsec
	mv $(CONFDIR)/ipsec.* /tmp
	rm -rf $(BINDIR)
	rm -f $(MANTREE)/man?/ipsec[._]*
	: kernel must be uninstalled manually



# some oddities meant for the developers, probably of no use to users

# make tags and TAGS files from ctags and etags for vi and emacs, respectively.
tags TAGS: dummy
	etags `find lib pluto klips/utils klips/net/ipsec -name '*.[ch]'`
	ctags `find lib pluto klips/utils klips/net/ipsec -name '*.[ch]'`

dummy:

# things in top to be linked up for developers
LINKUP=BUGS CHANGES COPYING CREDITS INSTALL Makefile Makefile.inc \
	Makefile.ver README

# at the moment there is no difference between snapshot and release build
snapready:	buildready
relready:	buildready
ready:		devready

# set up for build
buildready:
	rm -f dtrmakefile cvs.datemark
	cd doc ; $(MAKE) -s

# set up for developer use
devready:	verset
	cd .. ; for f in $(LINKUP) ; do ln -sfn top/$$f || exit 1 ; done

uml:	programs
	@echo XXX do some checks to see if all the manual pieces are done.
	-chmod +x testing/utils/make-uml.sh
	testing/utils/make-uml.sh `pwd`

check:	uml 
	@for d in $(SUBDIRS); do (cd $$d && $(MAKE) DESTDIR=${DESTDIR} checkprograms); done
	@for d in $(SUBDIRS); \
	do \
		echo ===================================; \
		echo Now making check in $$d; \
		echo ===================================; \
		(cd $$d && $(MAKE) DESTDIR=${DESTDIR} check);\
	done

