#
# Makefile for libpw
#

LIBPW_CONFIGURE_OPTS        = --disable-openldap --disable-sdl --disable-openssl --disable-vxml

LIBPW_CLEAN_FILES           = config.log config.status include/ptbuildopts.h plugins/config.log plugins/config.status plugins/pwlib \
                              plugins/vidinput_dc/Makefile make/ptbuildopts.mak make/ptlib-config

# Need to filter out any -f options because they break the configure process.
LDFLAGS                     := $(filter-out -fno-common,$(LDFLAGS))
LDFLAGS                     := $(filter-out -fno-builtin,$(LDFLAGS))

.PHONY: romfs clean distclean

all: Makefile
	$(MAKE) -f Makefile opt

Makefile:
	sh ./configure $(CONFIGURE_OPTS) $(LIBPW_CONFIGURE_OPTS)

ifneq ($(MAKECMDGOALS),distclean)
%: Makefile
	$(MAKE) -f Makefile $@
endif

romfs:
	$(ROMFSINST) lib/libpt_linux_arm_r.so.1.10.3 /lib/libpt_linux_arm_r.so.1.10.3

distclean:
clean:
	-$(MAKE) -f Makefile $@
	-rm -f a.out
	-rm -f Makefile
	-rm -f plugins/Makefile
	-rm -rf lib/
	-rm -rf $(LIBPW_CLEAN_FILES)
