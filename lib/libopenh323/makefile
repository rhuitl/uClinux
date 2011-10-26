#
# Makefile for libopenh323
#

LIBOPENH323_CONFIGURE_OPTS      = --disable-video --disable-versioncheck \
                                  --enable-minsize --disable-asntracing --disable-ixj \
                                  HAS_PTLIB=1 PWLIBDIR="$(ROOTDIR)/lib/pwlib"

LIBOPENH323_CLEAN_FILES         = autom4te.cache config.log config.status include/openh323buildopts.h openh323u.mak plugins/audio/G726/Makefile \
                                  plugins/audio/G726/obj plugins/audio/GSM0610/Makefile plugins/audio/GSM0610/obj plugins/audio/gsm-amr/Makefile \
                                  plugins/audio/iLBC/Makefile plugins/audio/iLBC/obj plugins/audio/IMA_ADPCM/Makefile plugins/audio/IMA_ADPCM/obj \
                                  plugins/audio/LPC_10/Makefile plugins/audio/LPC_10/obj plugins/audio/Speex/Makefile plugins/audio/Speex/obj \
                                  plugins/config.log plugins/config.status


# Need to filter out any -f options because they break the configure process.
LDFLAGS                         := $(filter-out -fno-common,$(LDFLAGS))
LDFLAGS                         := $(filter-out -fno-builtin,$(LDFLAGS))

.PHONY: romfs clean distclean

all: Makefile
	$(MAKE) -f Makefile opt

Makefile:
	sh ./configure $(CONFIGURE_OPTS) $(LIBOPENH323_CONFIGURE_OPTS)

ifneq ($(MAKECMDGOALS),distclean)
%: Makefile
	$(MAKE) -f Makefile $@
endif

romfs:
	$(ROMFSINST) lib/libh323_linux_arm_n.so.1.19.0 /lib/libh323_linux_arm_n.so.1.19.0


distclean:
clean:
	$(MAKE) -f Makefile $@
	-rm -f Makefile
	-rm -rf lib/
	-rm -rf $(LIBOPENH323_CLEAN_FILES)
