############################################################################

#
# Makefile -- Top level dist makefile.
#
# Copyright (c) 2001-2007, SnapGear (www.snapgear.com)
# Copyright (c) 2001, Lineo
#

############################################################################
#
# Lets work out what the user wants, and if they have configured us yet
#

ifeq (.config,$(wildcard .config))
all: tools automake subdirs romfs image
else
all: config_error
endif

ROOTDIR = $(shell pwd)

include vendors/config/common/config.arch

############################################################################

DIRS    = $(VENDOR_TOPDIRS) include lib include user


.PHONY: tools
tools: ucfront cksum
	chmod +x tools/romfs-inst.sh tools/modules-alias.sh tools/build-udev-perms.sh

.PHONY: ucfront
ucfront: tools/ucfront/*.c
	$(MAKE) -C tools/ucfront
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront tools/ucfront-gcc
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront tools/ucfront-g++
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront-ld tools/ucfront-ld
	ln -sf $(ROOTDIR)/tools/ucfront/jlibtool tools/jlibtool

.PHONY: cksum
cksum: tools/cksum
tools/cksum: tools/sg-cksum/*.c
	$(MAKE) -C tools/sg-cksum
	ln -sf $(ROOTDIR)/tools/sg-cksum/cksum tools/cksum

.PHONY: automake
automake:
	$(MAKE) -C config automake

############################################################################

#
# Config stuff, we recall ourselves to load the new config.arch before
# running the kernel and other config scripts
#

.PHONY: Kconfig
Kconfig:
	@chmod u+x config/mkconfig
	config/mkconfig > Kconfig

include config/Makefile.conf

SCRIPTS_BINARY_config     = conf
SCRIPTS_BINARY_menuconfig = mconf
SCRIPTS_BINARY_qconfig    = qconf
SCRIPTS_BINARY_gconfig    = gconf
SCRIPTS_BINARY_xconfig    = gconf
.PHONY: config menuconfig qconfig gconfig xconfig
menuconfig: mconf
qconfig: qconf
gconfig: gconf
xconfig: $(SCRIPTS_BINARY_xconfig)
config menuconfig qconfig gconfig xconfig: Kconfig conf
	KCONFIG_NOTIMESTAMP=1 $(SCRIPTSDIR)/$(SCRIPTS_BINARY_$@) Kconfig
	@if [ ! -f .config ]; then \
		echo; \
		echo "You have not saved your config, please re-run 'make $@'"; \
		echo; \
		exit 1; \
	 fi
	@chmod u+x config/setconfig
	@config/setconfig defaults
	@if egrep "^CONFIG_DEFAULTS_KERNEL=y" .config > /dev/null; then \
		$(MAKE) linux_$@; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_MODULES=y" .config > /dev/null; then \
		$(MAKE) modules_$@; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_VENDOR=y" .config > /dev/null; then \
		$(MAKE) myconfig_$@; \
	 fi
	@config/setconfig final

.PHONY: oldconfig
oldconfig: Kconfig conf
	KCONFIG_NOTIMESTAMP=1 $(SCRIPTSDIR)/conf -o Kconfig
	@chmod u+x config/setconfig
	@config/setconfig defaults
	@$(MAKE) oldconfig_linux
	@$(MAKE) oldconfig_modules
	@$(MAKE) oldconfig_config
	@$(MAKE) oldconfig_uClibc
	@config/setconfig final

.PHONY: generated_headers
generated_headers:
	if [ ! -f $(LINUXDIR)/include/linux/autoconf.h ] ; then \
		ln -sf $(ROOTDIR)/$(LINUXDIR)/include/generated/autoconf.h $(LINUXDIR)/include/linux/autoconf.h ; \
	fi

.PHONY: modules
modules: generated_headers
	. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(LINUXDIR)/modules ] || mkdir $(LINUXDIR)/modules; \
		$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) modules || exit 1; \
	fi

.PHONY: modules_install
modules_install:
	. $(LINUX_CONFIG); \
	. $(CONFIG_CONFIG); \
	if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(ROMFSDIR)/lib/modules ] || mkdir -p $(ROMFSDIR)/lib/modules; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) INSTALL_MOD_CMD="$(ROMFSINST) -S -r \"\"" INSTALL_MOD_PATH=$(ROMFSDIR) DEPMOD="$(ROOTDIR)/user/busybox/examples/depmod.pl" modules_install; \
		rm -f $(ROMFSDIR)/lib/modules/*/build; \
		rm -f $(ROMFSDIR)/lib/modules/*/source; \
		find $(ROMFSDIR)/lib/modules -type f -name "*o" | xargs -r $(STRIP) -R .comment -R .note -g --strip-unneeded; \
		if [ "$$CONFIG_USER_BUSYBOX_FEATURE_MODPROBE_FANCY_ALIAS" = "y" ]; \
		then \
			find $(ROMFSDIR)/lib/modules -type f -name "*o" | \
			/bin/sh $(ROOTDIR)/tools/modules-alias.sh \
					$(ROMFSDIR)/etc/modprobe.conf;\
		fi; \
	fi

linux_%:
	KCONFIG_NOTIMESTAMP=1 $(MAKEARCH_KERNEL) -C $(LINUXDIR) $(patsubst linux_%,%,$@)
modules_%:
	[ ! -d modules ] || KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C modules $(patsubst modules_%,%,$@)
myconfig_%:
	KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C config $(patsubst myconfig_%,%,$@)
oldconfig_config: myconfig_oldconfig
oldconfig_modules: modules_oldconfig
oldconfig_linux: linux_oldconfig
oldconfig_uClibc:
	[ -z "$(findstring uClibc,$(LIBCDIR))" ] || KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C $(LIBCDIR) oldconfig

############################################################################
#
# normal make targets
#

.PHONY: romfs
romfs: romfs.newlog romfs.subdirs modules_install romfs.post

.PHONY: romfs.newlog
romfs.newlog:
	rm -f $(IMAGEDIR)/romfs-inst.log

.PHONY: romfs.subdirs
romfs.subdirs:
	for dir in vendors $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir romfs || exit 1 ; done

.PHONY: romfs.post
romfs.post:
	$(MAKEARCH) -C vendors romfs.post
	-find $(ROMFSDIR)/. -name CVS | xargs -r rm -rf
	. $(LINUXDIR)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
		$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) $(LINUXTARGET) || exit 1; \
	fi

.PHONY: image
image:
	[ -d $(IMAGEDIR) ] || mkdir $(IMAGEDIR)
	$(MAKEARCH) -C vendors image

.PHONY: release
release:
	$(MAKE) -C release release

.PHONY: single
single:
	$(MAKE) NON_SMP_BUILD=1

%_fullrelease:
	@echo "This target no longer works"
	@echo "Do a make -C release $@"
	exit 1
#
# fancy target that allows a vendor to have other top level
# make targets,  for example "make vendor_flash" will run the
# vendor_flash target in the vendors directory
#

vendor_%:
	$(MAKEARCH) -C vendors $@

.PHONY: linux
linux linux%_only:
	. $(LINUXDIR)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
		mkdir -p `dirname $$CONFIG_INITRAMFS_SOURCE`; \
		touch $$CONFIG_INITRAMFS_SOURCE || exit 1; \
	fi
	@if expr "$(LINUXDIR)" : 'linux-2\.[0-4].*' > /dev/null && \
			 [ ! -f $(LINUXDIR)/.depend ] ; then \
		echo "ERROR: you need to do a 'make dep' first" ; \
		exit 1 ; \
	fi
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) $(LINUXTARGET) || exit 1
	@if expr "$(LINUXDIR)" : 'linux-\(2.6\|3\).*' > /dev/null ; then \
		: ignore failure in headers_install; \
		$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) headers_install || true; \
	fi
	if [ -f $(LINUXDIR)/vmlinux ]; then \
		ln -f $(LINUXDIR)/vmlinux $(LINUXDIR)/linux ; \
	fi

.PHONY: sparse
sparse:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=1 $(LINUXTARGET) || exit 1

.PHONY: sparseall
sparseall:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=2 $(LINUXTARGET) || exit 1

.PHONY: subdirs
subdirs: linux modules
	for dir in $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir || exit 1 ; done

dep:
	@if [ ! -f $(LINUXDIR)/.config ] ; then \
		echo "ERROR: you need to do a 'make config' first" ; \
		exit 1 ; \
	fi
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) dep

# This one removes all executables from the tree and forces their relinking
.PHONY: relink
relink:
	find user prop vendors -type f -name '*.gdb' | sed 's/^\(.*\)\.gdb/\1 \1.gdb/' | xargs rm -f

clean: modules_clean
	for dir in $(LINUXDIR) $(DIRS); do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir clean ; done
	rm -rf $(ROMFSDIR)/*
	rm -rf $(STAGEDIR)/*
	rm -rf $(IMAGEDIR)/*
	rm -f $(LINUXDIR)/linux
	rm -f $(LINUXDIR)/include/asm
	rm -f $(LINUXDIR)/include/linux/autoconf.h
	rm -rf $(LINUXDIR)/net/ipsec/alg/libaes $(LINUXDIR)/net/ipsec/alg/perlasm

real_clean mrproper: clean
	[ -d "$(LINUXDIR)" ] && $(MAKEARCH_KERNEL) -C $(LINUXDIR) mrproper || :
	[ -d uClibc ] && $(MAKEARCH) -C uClibc distclean || :
	[ -d modules ] && $(MAKEARCH) -C modules distclean || :
	[ -d "$(RELDIR)" ] && $(MAKEARCH) -C $(RELDIR) clean || :
	-$(MAKEARCH) -C config clean
	rm -rf romfs Kconfig config.arch images
	rm -rf .config .config.old .oldconfig autoconf.h auto.conf

distclean: mrproper
	-$(MAKEARCH_KERNEL) -C $(LINUXDIR) distclean
	-rm -f user/tinylogin/applet_source_list user/tinylogin/config.h
	-rm -f lib/uClibc lib/glibc
	-$(MAKE) -C tools/ucfront clean
	-rm -f tools/ucfront-gcc tools/ucfront-g++ tools/ucfront-ld tools/jlibtool
	-$(MAKE) -C tools/sg-cksum clean
	-rm -f tools/cksum

.PHONY: bugreport
bugreport:
	rm -rf ./bugreport.tar.gz ./bugreport
	mkdir bugreport
	$(HOSTCC) -v 2> ./bugreport/host_vers
	$(CROSS_COMPILE)gcc -v 2> ./bugreport/toolchain_vers
	cp .config bugreport/
	mkdir bugreport/$(LINUXDIR)
	cp $(LINUXDIR)/.config bugreport/$(LINUXDIR)/
	if [ -f $(LIBCDIR)/.config ] ; then \
		set -e ; \
		mkdir bugreport/$(LIBCDIR) ; \
		cp $(LIBCDIR)/.config bugreport/$(LIBCDIR)/ ; \
	fi
	mkdir bugreport/config
	cp config/.config bugreport/config/
	tar czf bugreport.tar.gz bugreport
	rm -rf ./bugreport

%_only:
	@case "$(@)" in \
	single*) $(MAKE) NON_SMP_BUILD=1 `expr $(@) : 'single[_]*\(.*\)'` ;; \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(*);; \
	esac

%_clean:
	@case "$(@)" in \
	single*) $(MAKE) NON_SMP_BUILD=1 `expr $(@) : 'single[_]*\(.*\)'` ;; \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(*) clean;; \
	esac

%_romfs:
	@case "$(@)" in \
	single*) $(MAKE) NON_SMP_BUILD=1 `expr $(@) : 'single[_]*\(.*\)'` ;; \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(*) romfs;; \
	esac

vendors/%_defconfig:
	$(MAKE) $(*)_defconfig

%_defconfig: conf
	@if [ ! -f "vendors/$(*)/config.device" ]; then \
		echo "vendors/$(*)/config.device must exist first"; \
		exit 1; \
	 fi
	-$(MAKE) clean > /dev/null 2>&1
	cp vendors/$(*)/config.device .config
	chmod u+x config/setconfig
	yes "" | config/setconfig defaults
	config/setconfig final
	$(MAKE) dep

%_default: conf
	$(MAKE) $(*)_defconfig
	$(MAKE)

config_error:
	@echo "*************************************************"
	@echo "You have not run make config."
	@echo "The build sequence for this source tree is:"
	@echo "1. 'make config' or 'make xconfig'"
	@echo "2. 'make dep'"
	@echo "3. 'make'"
	@echo "*************************************************"
	@exit 1

prune: ucfront
	@for i in `ls -d linux-* | grep -v $(LINUXDIR)`; do \
		rm -fr $$i; \
	done
	$(MAKE) -C lib prune
	$(MAKE) -C user prune
	$(MAKE) -C vendors prune

dist-prep:
	-find $(ROOTDIR) -name 'Makefile*.bin' | while read t; do \
		$(MAKEARCH) -C `dirname $$t` -f `basename $$t` $@; \
	 done

help:
	@echo "Quick reference for various supported make commands."
	@echo "----------------------------------------------------"
	@echo ""
	@echo "make xconfig               Configure the target etc"
	@echo "make config                \""
	@echo "make menuconfig            \""
	@echo "make qconfig               \""
	@echo "make gconfig               \""
	@echo "make dep                   2.4 and earlier kernels need this step"
	@echo "make                       build the entire tree and final images"
	@echo "make clean                 clean out compiled files, but not config"
	@echo "make distclean             clean out all non-distributed files"
	@echo "make oldconfig             re-run the config without interaction"
	@echo "make linux                 compile the selected kernel only"
	@echo "make romfs                 install all files to romfs directory"
	@echo "make image                 combine romfs and kernel into final image"
	@echo "make modules               build all modules"
	@echo "make modules_install       install modules into romfs"
	@echo "make DIR_only              build just the directory DIR"
	@echo "make DIR_romfs             install files from directory DIR to romfs"
	@echo "make DIR_clean             clean just the directory DIR"
	@echo "make single                non-parallelised build"
	@echo "make single[make-target]   non-parallelised build of \"make-target\""
	@echo "make V/P_default           full default build for V=Vendor/P=Product"
	@echo "make prune                 clean out uncompiled source (be careful)"
	@echo ""
	@echo "Typically you want to start with this sequence before experimenting."
	@echo ""
	@echo "make config                select platform, kernel, etc, customise nothing."
	@echo "make dep                   optional but safe even on newer kernels."
	@echo "make                       build it as the creators intended."
	@exit 0
	

############################################################################
