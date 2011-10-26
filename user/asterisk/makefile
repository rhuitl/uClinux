#
# Makefile for Asterisk
#

# Explicity set the strip variable otherwise /usr/bin/strip is used.
# Turn off any option that we don't explicitly need.
ASTERISK_CONFIGURE_OPTS     = ac_cv_path_STRIP=$(STRIP) \
                              --with-h323=$(ROOTDIR)/lib/libopenh323 \
                              --with-pwlib=$(ROOTDIR)/lib/pwlib \
                              --without-kde --without-ncurses --without-curses \
                              --without-oss --without-qt --without-curl
ASTERISK_TEMP_INSTALL_DIR   = $(ROOTDIR)/user/asterisk/install

.PHONY: all clean distclean


# We need a special target for the dynamically generated Makefile.ast. 
# When compiling the h323 module (--with-h323) the build process dynamically 
# generates a new makefile (channels/h323/Makefile.ast) using some of the 
# variables from the h323 library (openh323). It then prints out a message to 
# say, "re-run make" and throws an error. This dep setup calls make twice, 
# ignoring the error code for the first run if we're making Makefile.ast.

all: makeopts channels/h323/Makefile.ast
	$(MAKE) -f Makefile $@

channels/h323/Makefile.ast:
	-$(MAKE) -f Makefile

makeopts:
	./configure $(CONFIGURE_OPTS) $(ASTERISK_CONFIGURE_OPTS)

%:
	$(MAKE) -f Makefile $@

romfs: all
	[ -d $(ROMFSDIR)/usr/lib/asterisk/modules ] || mkdir -p $(ROMFSDIR)/usr/lib/asterisk/modules 
	[ -d $(ROMFSDIR)/etc/asterisk ] || mkdir -p $(ROMFSDIR)/etc/asterisk
	DESTDIR=$(ASTERISK_TEMP_INSTALL_DIR) $(MAKE) -f Makefile install
	DESTDIR=$(ASTERISK_TEMP_INSTALL_DIR) $(MAKE) -f Makefile samples
	(cd install/usr/sbin; for i in `find . -type f -not -name stereorize -not -name streamplayer`; do $(ROMFSINST) $$i /sbin/$$i; done)
	$(ROMFSINST) -s /sbin/asterisk /sbin/rasterisk
	(cd install/usr/lib/asterisk/modules; for i in * ; do $(ROMFSINST) $$i /usr/lib/asterisk/modules/$$i; done)
	(cd install/etc/asterisk; for i in * ; do $(ROMFSINST) $$i /etc/asterisk/$$i; done)
	$(ROMFSINST) configs/asterisk_sgtest.conf /etc/asterisk/asterisk_sgtest.conf
	$(ROMFSINST) configs/sip_sgtest.conf /etc/asterisk/sip_sgtest.conf

clean distclean:
	rm -rf $(ASTERISK_TEMP_INSTALL_DIR)
	$(MAKE) -f Makefile $@
