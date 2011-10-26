noinst_PROGRAMS = pam_ldap.so
EXTRA_DIST = COPYING.LIB CVSVersionInfo.txt ChangeLog README \
	     ldap.conf pam.conf pam_ldap.spec pam.d

pam_ldap_so_SOURCES = pam_ldap.c pam_ldap.h md5.c md5.h
pam_ldap_so_LDFLAGS = @pam_ldap_so_LDFLAGS@

man_MANS = pam_ldap.5

DEFS = @DEFS@

if USE_NATIVE_LINKER
NATIVE_LINK = $(pam_ldap_so_LD) $(AM_LDFLAGS) -o $@ 
else
GNU_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
endif

# This is horrible but appears to be the only way to work with
# recent versions of automake. Any better ideas, let me know.
LINK = $(NATIVE_LINK) $(GNU_LINK)

install-exec-local: pam_ldap.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/security
if EXTENSION_SO
	$(INSTALL_PROGRAM) -o root -g root pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so
else
if EXTENSION_1
	$(INSTALL_PROGRAM) -o root -g root pam_ldap.so $(DESTDIR)$(libdir)/security/libpam_ldap.1
else
	$(INSTALL_PROGRAM) -o root -g root pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so.1
	(cd $(DESTDIR)$(libdir)/security; rm -f pam_ldap.so; ln -s pam_ldap.so.1 pam_ldap.so)
endif
endif

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(sysconfdir)/ldap.conf; then \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
		$(INSTALL_DATA) -o root -g root $(srcdir)/ldap.conf $(DESTDIR)$(sysconfdir)/ldap.conf; \
	fi

uninstall-local:
	@$(NORMAL_UNINSTALL)

