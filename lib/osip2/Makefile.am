EXTRA_DIST = README BUGS FEATURES HISTORY autogen.sh libosip2.pc.in

SUBDIRS = include src scripts help platform debian

rpm-package:
	cd platform && $(MAKE) rpm-package

deb:
	dpkg-buildpackage -rfakeroot

upload: dist
	@echo "######## Maintainer only ##########";
	@echo "building files for upload in ftp://ftp-upload.gnu.org/incoming/ftp";
	@echo "building: $(PACKAGE)-$(VERSION).tar.gz.sig";
	gpg -b $(PACKAGE)-$(VERSION).tar.gz
	echo "directory: osip" > $(PACKAGE)-$(VERSION).tar.gz.directive
	@echo "building: $(PACKAGE)-$(VERSION).tar.gz.directive.asc";
	gpg --clearsign $(PACKAGE)-$(VERSION).tar.gz.directive

indent:
	indent */*/*.c
	indent */*/*.h
	rm -rf */*/*.c~
	rm -rf */*/*.h~

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosip2.pc
