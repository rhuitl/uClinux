#
# Makefile for Asterisk Addons (MySQL module etc)
#

ASTERISK_ADDONS_CONFIGURE_OPTS          = --with-mysqlclient=. \
                                          --with-asterisk=$(ROOTDIR)/user/asterisk \
                                          --without-ncurses --without-curses

ASTERISK_ADDONS_TEMP_INSTALL_DIR        = $(ROOTDIR)/user/asterisk-addons/install


.PHONY: all romfs clean distclean

all: makeopts asterisk-ooh323c/Makefile
	$(MAKE) -f Makefile all

asterisk-ooh323c/Makefile: makeopts
	cd asterisk-ooh323c && chmod a+x configure && ac_cv_func_malloc_0_nonnull=yes ./configure $(CONFIGURE_OPTS)

makeopts:
	[[ -h mysql ]] || ln -s $(ROOTDIR)/user/mysql/include mysql
	[[ -d bin ]] || mkdir bin
	[[ -f bin/mysql_config ]] || ( touch bin/mysql_config; chmod a+x bin/mysql_config )
	MYSQLCLIENT_INCLUDE="-I." PATH=".:$$PATH" \
	sh ./configure $(CONFIGURE_OPTS) $(ASTERISK_ADDONS_CONFIGURE_OPTS)

%:
	$(MAKE) -f Makefile $@

romfs: all
	mkdir -p install/usr/lib/asterisk/modules
	DESTDIR=$(ASTERISK_ADDONS_TEMP_INSTALL_DIR) $(MAKE) -f Makefile install
	[ -d $(ROMFSDIR)/usr/lib/asterisk/modules ] || mkdir -p $(ROMFSDIR)/usr/lib/asterisk/modules 
	( cd install/usr/lib/asterisk/modules; for i in * ; do $(ROMFSINST) $$i /usr/lib/asterisk/modules/$$i; done )

clean distclean:
	rm -f mysql
	rm -f makeopts
	rm -rf bin
	rm -rf install
	$(MAKE) -f Makefile $@
