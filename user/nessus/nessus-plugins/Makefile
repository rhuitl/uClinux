include nessus.tmpl

all : mkplugins

mkplugins :
	cd plugins && ./make_world
	
clean : 
	cd plugins && ./make_world clean

install-updater :
	test -d $(DESTDIR)${sbindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${sbindir}
	$(INSTALL) -o $(installuser) -m 0555 nessus-update-plugins \
		$(DESTDIR)${sbindir}
	@test -d $(DESTDIR)${mandir}/man8 || $(INSTALL_DIR) $(DESTDIR)${mandir}/man8
	$(INSTALL) -o $(installuser) -m 0444 docs/nessus-update-plugins.8 \
		$(DESTDIR)${mandir}/man8

install-dirs:
	test -d $(DESTDIR)${libdir}/nessus || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${libdir}/nessus
	test -d $(DESTDIR)${libdir}/nessus/plugins || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${libdir}/nessus/plugins
	
install-nasl:	install-dirs
	for scripts in scripts/*.nasl; do \
	$(INSTALL) -o $(installuser) -m 444 $$scripts \
		$(DESTDIR)${libdir}/nessus/plugins; \
	done

install-inc: install-dirs
	for scripts in scripts/*.inc; do \
	$(INSTALL) -o $(installuser) -m 444 $$scripts \
		$(DESTDIR)${libdir}/nessus/plugins; \
	done

install-nes: install-dirs
	for plugins in bin/*.nes; do \
	$(INSTALL) -o $(installuser) -m 555 $$plugins \
		$(DESTDIR)${libdir}/nessus/plugins; \
	done

install-conf:
	test -d $(DESTDIR)${localstatedir}/nessus || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${localstatedir}/nessus

install-man:
	test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${mandir}/man1
	$(INSTALL) -m 644 pf/nessus-build.1 $(DESTDIR)${mandir}/man1

install : all \
	install-dirs install-nasl install-inc install-nes \
	install-man install-conf $(INSTALL_UPDATER) 
	
	$(INSTALL_DIR) -m 755 $(DESTDIR)${libdir}/nessus/plugins_factory
	$(INSTALL) -m 444 pf/Makefile $(DESTDIR)${libdir}/nessus/plugins_factory
	$(INSTALL) -m 444 libtool $(DESTDIR)${libdir}/nessus/plugins_factory
	$(INSTALL) -m 444 nessus.tmpl $(DESTDIR)${libdir}/nessus/plugins_factory
	test -d $(DESTDIR)${prefix}/bin || $(INSTALL_DIR) -m 755 \
		$(DESTDIR)${prefix}/bin
	$(INSTALL) -m 755 pf/nessus-build $(DESTDIR)${prefix}/bin/

distclean : clean
	rm -f libtool config.cache config.status config.log nessus.tmpl nessus-update-plugins
	rm -f bin/*.nes pf/nessus-build
	
