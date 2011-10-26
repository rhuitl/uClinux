#
# this makefile gets recursed through by various bits of the build
# so we need to only setup some things when invoked from outside
# this directory.
#
# davidm@snapgear.com
#

IN_LIBSSL := true
export IN_LIBSSL

#
# we need to do different things for 64 bit systems
#
ifdef CONFIG_64BIT
MACHINE=uClinux-dist64
else
MACHINE=uClinux-dist
endif

CONFIG_OPTS  := --prefix=// --install_prefix=$(shell pwd)/build/install

ifdef CONFIG_USER_FLATFSD_FLATFSD
CONFIG_OPTS += --openssldir=/etc/config
else
CONFIG_OPTS += --openssldir=/etc
endif
ifdef DISABLE_SHARED_SSL
CONFIG_OPTS += no-shared
else
CONFIG_OPTS += shared
endif

CONFIG_OPTS += no-rc2
CONFIG_OPTS += no-krb5
CONFIG_OPTS += no-rc5
CONFIG_OPTS += no-md2
CONFIG_OPTS += no-mdc2
CONFIG_OPTS += no-idea
#CONFIG_OPTS += no-pem
#CONFIG_OPTS += no-md5
#CONFIG_OPTS += no-sha
#CONFIG_OPTS += no-hmac
#CONFIG_OPTS += no-des
#CONFIG_OPTS += no-aes
#CONFIG_OPTS += no-bn
CONFIG_OPTS += no-ec
#CONFIG_OPTS += no-rsa
#CONFIG_OPTS += no-dsa
CONFIG_OPTS += no-ecdsa
#CONFIG_OPTS += no-dh
CONFIG_OPTS += no-ecdh
CONFIG_OPTS += no-dso
#CONFIG_OPTS += no-engine
#CONFIG_OPTS += no-buffer
#CONFIG_OPTS += no-bio
#CONFIG_OPTS += no-stack
#CONFIG_OPTS += no-lhash
#CONFIG_OPTS += no-rand
CONFIG_OPTS += no-err
#CONFIG_OPTS += no-evp
#CONFIG_OPTS += no-asn1
#CONFIG_OPTS += no-x509
#CONFIG_OPTS += no-x509v3
#CONFIG_OPTS += no-txt_db
#CONFIG_OPTS += no-pkcs7
#CONFIG_OPTS += no-pkcs12
#CONFIG_OPTS += no-comp
#CONFIG_OPTS += no-ocsp
#CONFIG_OPTS += no-ui
#CONFIG_OPTS += no-store
#CONFIG_OPTS += no-pqueue
#CONFIG_OPTS += no-tlsext
#CONFIG_OPTS += no-ssl2
#CONFIG_OPTS += no-ssl3

# REVISIT: It would be better to have OPENSSL config options
# which turn on this support as needed
ifeq ($(CONFIG_USER_NESSUS_NASL)$(CONFIG_USER_SSH_SSH),)
CONFIG_OPTS += no-ripemd
CONFIG_OPTS += no-cast
CONFIG_OPTS += no-rc4
endif

ifeq ($(CONFIG_USER_NESSUS_NASL)$(CONFIG_USER_SSH_SSH)$(CONFIG_PROP_SSCEP_SSCEP),)
CONFIG_OPTS += no-bf
endif

ifeq ($(CONFIG_USER_OPENVPN_OPENVPN)$(CONFIG_USER_WGET),)
CONFIG_OPTS += no-md4
endif

ifdef CONFIG_OCF_OCF
CONFIG_OPTS += --with-cryptodev
#CONFIG_OPTS += --with-cryptodev-digests
endif

#
# if you want engines (they are dl loaded),  a few things
# need to be setup,  you will also need to mod everything
# to link against -ldl if it uses libcrypto.  By default we
# disable it (cryptodev suport is still included).
#
ifdef YOU_WANT_DYNAMIC_HW_ENGINES_ENABLED
LIBSSL_dlfcn = dlfcn
else
CONFIG_OPTS += no-hw
LIBSSL_dlfcn =
endif

#
# our libs aren't in the default location yet
#
LDFLAGS += -L$(ROOTDIR)/lib/libssl/build
export LDFLAGS

all: build/configured
	$(MAKE) -j1 -C build
	$(MAKE) -j1 -C build install_sw

############################################################################
#
# we may not have the library here, so setup for downloading if needed

ifeq ($(wildcard Configure),)

openssl-0.9.8i-url := http://www.openssl.org/source/openssl-0.9.8i.tar.gz
openssl-0.9.8k-url := http://www.openssl.org/source/openssl-0.9.8k.tar.gz
openssl-0.9.8n-url := http://www.openssl.org/source/openssl-0.9.8n.tar.gz
openssl-0.9.8r-url := http://www.openssl.org/source/openssl-0.9.8r.tar.gz

SRC_DIR := openssl-0.9.8r

WGET ?= wget

%.tar.bz2 %.tar.gz:
	@echo "Downloading $* ..."
	@[ -d "$$HOME/.downloads" ] || mkdir ~/.downloads
	@if [ ! -f "$$HOME/.downloads/$@" ]; then \
		(cd ~/.downloads; $(WGET) "$($*-url)"); \
	fi
	@if [ -f "$$HOME/.downloads/$@" ]; then \
			ln -fs "$$HOME/.downloads/$@" $@; \
	fi
	if [ ! -f "$@" ]; then \
		echo "Cannot find download for $@" >&2 ; \
		exit 1; \
	fi

$(SRC_DIR)/Configure $(SRC_DIR)/config: makefile $(SRC_DIR).tar.gz \
		patches/$(SRC_DIR).patch
	rm -rf $(SRC_DIR) build
	gunzip < $(SRC_DIR).tar.gz | tar xf -
	patch -p0 < patches/$(SRC_DIR).patch
	touch $(SRC_DIR)/Configure $(SRC_DIR)/config

else

SRC_DIR := .

endif

############################################################################

build/configured: makefile $(SRC_DIR)/config $(SRC_DIR)/Configure
	rm -rf build
	(cd $(SRC_DIR)/.; find . -type d) > .dirs
	(cd $(SRC_DIR)/.; find . ! -type d) | grep -v ./makefile > .files
	while read t; do mkdir -p build/$$t; done < .dirs
	while read t; do ln -s `pwd`/$(SRC_DIR)/$$t build/$$t; done < .files
	rm -f .dirs .files
	chmod +x build/config
	cd build; CROSS_COMPILE= MACHINE=$(MACHINE) ./config $(CONFIG_OPTS)
	$(MAKE) -C build depend
	$(MAKE) -C build links
	touch build/configured

clean:
	-rm -rf build

romfs:
	cd build/install/lib; \
	for i in *.so*; do \
		if [ -L $$i ]; then \
			$(ROMFSINST) -s `find $$i -printf %l` /lib/$$i; \
		elif [ -f $$i ]; then \
			$(ROMFSINST) /lib/$$i; \
		fi; \
	done

romfs_user:
	$(ROMFSINST) -e CONFIG_USER_OPENSSL_APPS build/install/bin/openssl /bin/openssl
	# $(ROMFSINST) -e CONFIG_USER_OPENSSL_APPS build/install/bin/c_rehash /bin/c_rehash


