CONFIG_LANGUAGE ?= english
ifeq ($(CONFIG_LANGUAGE),)
CONFIG_LANGUAGE=english
endif

SQUID_LANG := English
ifdef CONFIG_LANG_JAPANESE
SQUID_LANG += Japanese
endif
ifdef CONFIG_LANG_CHINESE
SQUID_LANG += Simplify_Chinese
endif

CONFOPTS=--prefix= \
		--with-headers=$(ROOTDIR)/$(LINUXDIR)/include		\
		--sysconfdir=/etc/config				\
		--datadir=/etc --libexecdir=/bin			\
		--enable-err-languages="$(sort $(SQUID_LANG))"		\
		--enable-default-err-language=English			\
		--enable-linux-netfilter --disable-ident-lookups	\
		--enable-icap-support \
		--enable-dependency-tracking \
		--with-maxfd=8192

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
	$(MAKE) -C build/errors $@
	$(MAKE) -C build/icons $@
	$(MAKE) -C build/src $@
