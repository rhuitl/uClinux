
.PHONY: all clean distclean

all: .dep
	PREFIX="" $(MAKE) -f Makefile


.dep:
	PREFIX="" $(MAKE) -f Makefile dep
	touch .dep

%:
	$(MAKE) -f Makefile $@

romfs: all
	BASEDIR=$(ROOTDIR)/user/ser/install PREFIX="" $(MAKE) -f Makefile install
	[ -d $(ROMFSDIR)/etc/ser ] || mkdir $(ROMFSDIR)/etc/ser
	$(ROMFSINST) install/etc/ser/ser.cfg /etc/ser/ser.cfg
	$(ROMFSINST) examples/ser_sgtest.cfg /etc/ser/ser_sgtest.cfg
	for i in install/sbin/* ; do $(ROMFSINST) $$i /sbin/`basename $$i`; done
	for i in install/lib/ser/* ; do $(ROMFSINST) $$i /lib/ser/`basename $$i`; done

clean distclean:
	rm -f .dep
	rm -rf $(ROOTDIR)/user/ser/install
	$(MAKE) -f Makefile $@

