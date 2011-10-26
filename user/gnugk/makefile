#
# Makefile for GNU GateKeeper
#

GNUGK_CONFIGURE_OPTS        = --enable-mysql --with-mysql-include-dir=$(ROOTDIR)/user/mysql/include \
                              --with-mysql-lib-dir=$(ROOTDIR)/user/mysql/libmysql/.libs \
                              --disable-pgsql --disable-firebird
GNUGK_PRECONFIGURE_OPTS     = HAS_PTLIB=1 HAS_PWLIB_VERSION_FILE=1 HAS_OPENH323=1 HAS_OPENH323_VERSIONFILE=1 \
                              PWLIBDIR="$(ROOTDIR)/lib/pwlib" \
                              OPENH323DIR="$(ROOTDIR)/lib/libopenh323" 

GNUGK_CLEAN_FILES           = config.cache config.log config.status


.PHONY: romfs clean distclean

all: Makefile
	$(MAKE) -f Makefile opt

Makefile:
	$(GNUGK_PRECONFIGURE_OPTS) sh ./configure $(CONFIGURE_OPTS) $(GNUGK_CONFIGURE_OPTS)

ifneq ($(MAKECMDGOALS),distclean)
%: Makefile
	$(MAKE) -f Makefile $@
endif

romfs:
	$(ROMFSINST) obj_linux_arm_n/gnugk /bin/gnugk

clean:
	$(MAKE) -f Makefile $@

distclean:
	-rm -f Makefile
	-rm -rf obj_*
	-rm -rf $(GNUGK_CLEAN_FILES)
