
# CONFOPTS = --disable-shared --with-raddbdir=/etc/config
CONFOPTS =  --with-raddbdir=/etc/freeradius
CONFOPTS += --without-snmp --without-openssl
#CONFOPTS += --with-openssl-includes=$(ROOTDIR)/include/openssl
#CONFOPTS += --with-openssl-libraries=$(ROOTDIR)/lib

# freeradius overrides DESTDIR with R for some crazy reason
export R := $(shell pwd)/build/freeradius-server-2.1.6-install

# make sure we use the freeradius libtool
MAKEVARS :=

# make sure we do not do parallel builds
MAKEFLAGS := $(MAKEFLAGS) -j1

AUTOMAKE_ROMFS = freeradius_romfs

URL = ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.6.tar.gz
include $(ROOTDIR)/tools/automake.inc

freeradius_romfs:
	$(ROMFSINST) build/freeradius-server-2.1.6-install/lib /lib
	$(ROMFSINST) build/freeradius-server-2.1.6-install/bin /bin
	$(ROMFSINST) build/freeradius-server-2.1.6-install/sbin /sbin
	