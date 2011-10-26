include nasl.tmpl

all: 
	cd nasl && ${MAKE}

nasl.tmpl: nasl.tmpl.in configure
	$(SHELL) configure $(CONFIGURE_ARGS)
	touch $@

install: all
	cd nasl && ${MAKE} install
	test -d $(DESTDIR)${includedir}/nessus || $(INSTALL_DIR) -m 755 $(DESTDIR)${includedir}/nessus
	$(INSTALL) -c -m 0444 include/nasl.h $(DESTDIR)${includedir}/nessus
	test -d $(DESTDIR)${bindir} || $(INSTALL_DIR) -m 755 $(DESTDIR)${bindir}
	$(INSTALL) -c -m 0755 nasl-config $(DESTDIR)${bindir}/nasl-config
	test -d $(DESTDIR)${mandir}/man1 || $(INSTALL_DIR) -m 755 $(DESTDIR)${mandir}/man1
	$(INSTALL) -c -m 0644 doc/nasl-config.1 $(DESTDIR)${mandir}/man1
	$(INSTALL) -c -m 0644 doc/nasl.1 $(DESTDIR)${mandir}/man1
	$(INSTALL) -c -m 0644 doc/nasl-config.1 $(DESTDIR)${mandir}/man1
	test -d $(DESTDIR)${localstatedir}/nessus || $(INSTALL_DIR) -m 755 $(DESTDIR)${localstatedir}/nessus
	$(INSTALL) -c -m 0644 doc/nessus_org.pem $(DESTDIR)${localstatedir}/nessus/nessus_org.pem


	@echo
	@echo ' --------------------------------------------------------------'
	@echo ' libnasl has been sucessfully installed. '
	@echo " Make sure that $(bindir) is in your PATH before you"
	@echo " continue "
	@echo ' --------------------------------------------------------------'
	@echo
clean :
	cd nasl && ${MAKE} clean

distclean : clean
	rm -f ${rootdir}/include/config.h libtool config.cache \
	config.status config.log
	cd nasl && ${MAKE} distclean
	rm -f nasl.tmpl nasl-config

