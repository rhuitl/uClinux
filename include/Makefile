#
# build a smart "symlink" header tree so the compile lines are
# much shorter and the problems with include paths are much smaller
#
# David McCullough <davidm@snapgear.com>
#

#
# At least one architecture now uses a common include directory in the
# MMU and non-MMU kernel. Both m68k and m68knommu use the m68k includes.
# And i386 has now become x86 (from linux-2.6.29 onwards).
#
ALTARCH=$(subst i386,x86,$(subst nommu,,$(ARCH)))

#
# glibc contains lots of nasty headers in a bad location,  so we need
# to cheat a little here
#

include $(ROOTDIR)/vendors/config/common/config.arch
ifneq ($(wildcard $(ROOTDIR)/$(LINUXDIR)/usr/include),)
LINUXAUTOCONF = $(ROOTDIR)/$(LINUXDIR)/include/linux/autoconf.h
LINKHDRS = \
	$(ROOTDIR)/$(LINUXDIR)/usr/include/*,. \
	$(LINUXAUTOCONF),linux
else
LINUXAUTOCONF = $(ROOTDIR)/$(LINUXDIR)/include/generated/autoconf.h
LINKHDRS = \
	$(ROOTDIR)/$(LINUXDIR)/include/linux,. \
	$(LINUXAUTOCONF),linux \
	$(ROOTDIR)/$(LINUXDIR)/arch/$(ARCH)/include/asm-*,. \
	$(ROOTDIR)/$(LINUXDIR)/include/asm-*,. \
	$(ROOTDIR)/$(LINUXDIR)/arch/$(ARCH)/include/asm,. \
	$(ROOTDIR)/$(LINUXDIR)/arch/$(ALTARCH)/include/asm,. \
	$(ROOTDIR)/$(LINUXDIR)/include/asm,. \
	$(ROOTDIR)/$(LINUXDIR)/include/mtd,.
endif

LINKHDRS += \
	$(ROOTDIR)/autoconf.h,vendor \
	$(ROOTDIR)/config,. \
	$(ROOTDIR)/modules/autoconf.h,modules \
	$(ROOTDIR)/modules/ocf/cryptodev.h,crypto \
	$(ROOTDIR)/user/gdb/include/ansidecl.h,. \
	$(ROOTDIR)/user/gdb/include/symcat.h,.

#
# link in the files,  avoid missing or CVS files,  existing files take
# precedance so we do not try to overwrite them
#

INCDIR=$(STAGEDIR)/include
AUTOCONF=$(INCDIR)/vendor/autoconf.h $(INCDIR)/config/autoconf.h $(INCDIR)/modules/autoconf.h $(INCDIR)/linux/autoconf.h

TARGETS=
ifdef HOSTBUILD
TARGETS+=$(AUTOCONF)
else
TARGETS+=link
ifndef CONFIG_DEFAULTS_LIBC_NONE
TARGETS+=cpplink
endif
endif

.PHONY: all
all: $(TARGETS)

.PHONY: link
link:
	@echo "Making symlinks in $(INCDIR)"
	@mkdir -p $(INCDIR)
	@for p in $(LINKHDRS); do \
		src=`expr "$$p" : '\(.*\),.*'` ; \
		dst=$(INCDIR)/`expr "$$p" : '.*,\(.*\)'` ; \
		for i in $$src; do \
			[ ! -e "$$i" ] && continue; \
			[ "`basename $$i`" = CVS ] && continue; \
			[ -L "$$dst/`basename $$i`" ] && continue; \
			[ -d $$dst ] || mkdir $$dst; \
			ln -s $$i $$dst/.; \
		done ; \
	done

.PHONY: cpplink
cpplink:
	@echo "Making include/c++ symlink to compiler c++ includes"
	@rm -f $(INCDIR)/c++
	@ln -s /usr/local/include/g++-v3 $(INCDIR)/c++
	@for i in `$(CXX) -v -E -xc++ /dev/null 2>&1 | sed -e '/^Reading specs/,/^#include <\.\.\.>/d' -e '/End of search list/Q'`; do \
		if [ -f $$i/new ]; then rm -f $(INCDIR)/c++; ln -s $$i $(INCDIR)/c++; break; fi; \
	done
	@rm -f $(INCDIR)/bits ; \
	 GCCVER=`$(CC) -dumpversion` ; \
	 GCCMACH=`$(CC) -dumpmachine` ; \
	 GCCMULTI=`$(CC) -print-multi-directory` ; \
	 GCCPATH=`$(CC) -print-libgcc-file-name | sed -e 's?/lib/gcc/.*$$??g'` ; \
	 GPLUSBITS="$$GCCPATH/$$GCCMACH/include/c++/$$GCCVER/$$GCCMACH/$$GCCMULTI/bits $$GCCPATH/include/c++/$$GCCVER/$$GCCMACH/$$GCCMULTI/bits"; \
	 echo "Checking for modern c++ bits..."; \
	 for i in $$GPLUSBITS; do \
		 if [ -d $$i ] ; then \
			echo "Using modern c++ bits, $$i" ; \
			ln -s $$i $(INCDIR)/bits ; \
			break; \
		 fi; \
	 done

$(INCDIR)/vendor/autoconf.h: $(ROOTDIR)/autoconf.h
	@mkdir -p $(INCDIR)/vendor
	grep -v '^#undef' $^ | grep -vw $(CONFIG_BLACKLIST_GREP) >$@

$(INCDIR)/config/autoconf.h: $(ROOTDIR)/config/autoconf.h
	@mkdir -p $(INCDIR)/config
	grep -v '^#undef' $^ | grep -vw $(CONFIG_BLACKLIST_GREP) >$@

$(INCDIR)/modules/autoconf.h: $(ROOTDIR)/modules/autoconf.h
	@mkdir -p $(INCDIR)/modules
	grep -v '^#undef' $^ | grep -vw $(CONFIG_BLACKLIST_GREP) >$@

$(INCDIR)/linux/autoconf.h: $(LINUXAUTOCONF)
	@mkdir -p $(INCDIR)/linux
	grep -v '^#undef' $^ | grep -vw $(CONFIG_BLACKLIST_GREP) >$@

.PHONY: romfs
romfs:

.PHONY: clean
clean:
	-find $(INCDIR) -depth -type l -a ! -name Makefile | xargs rm > /dev/null 2>&1 || exit 0
	-find $(INCDIR) -depth -type d | grep -v .svn | xargs rmdir > /dev/null 2>&1 || exit 0
	-rm $(AUTOCONF)
