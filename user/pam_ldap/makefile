.EXPORT_ALL_VARIABLES:

CONFOPTS = --with-ldap-conf-file=/etc/config/ldap.conf				\
		--with-ldap-secret-file=/etc/config/ldap.secret
CFLAGS += -I$(ROOTDIR)/user/pam_ldap/build
CFLAGS += -I$(ROOTDIR)/user/pam_ldap
LDFLAGS += -static

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/pam_ldap.so /lib/security/pam_ldap.so
