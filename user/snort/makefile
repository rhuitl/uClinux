.EXPORT_ALL_VARIABLES:

CONFOPTS =--enable-dependency-tracking						\
		--disable-shared						\
		--enable-inline 						\
		--disable-dynamicplugin 					\
		--with-libipq-includes=$(ROOTDIR)/user/iptables/include/libipq	\
		--with-libipq-libraries=$(ROOTDIR)/user/iptables/build/libipq 	\
		--with-libnet=$(ROOTDIR)/lib/Libnet				\
		--with-libnet-includes=$(ROOTDIR)/lib/Libnet/include		\
		--with-libnet-libraries=$(ROOTDIR)/lib/Libnet/lib
LDFLAGS += -L$(ROOTDIR)/user/iptables/build/libipq

ifdef CONFIG_USER_MYSQL_CLIB
CONFOPTS += --with-mysql=$(ROOTDIR)/user/mysql
LDFLAGS += -L$(ROOTDIR)/user/mysql/libmysql
LDFLAGS += -L$(ROOTDIR)/lib/Libnet/lib -lnet
endif

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
	$(ROMFSINST) build/src/snort /bin/snort
	$(ROMFSINST) -s /bin/snort /bin/snort-inline
	$(ROMFSINST) std-rules/local.rules /etc/default/local.rules
	$(ROMFSINST) drop-rules/local.rules /etc/default/local-drop.rules
	# Copy default rule set across
	[ -d $(ROMFSDIR)/etc/snort ] || mkdir $(ROMFSDIR)/etc/snort
	[ -d $(ROMFSDIR)/etc/snort/drop-rules ] || mkdir $(ROMFSDIR)/etc/snort/drop-rules
	for i in std-rules/*.rules; do $(ROMFSINST) $$i /etc/snort/`basename $$i`; done
	for i in drop-rules/*.rules; do $(ROMFSINST) $$i /etc/snort/drop-rules/`basename $$i`; done
	# Local rules go elsewhere...
	if [ -f $(ROMFSDIR)/etc/snort/local.rules ]; then rm -f $(ROMFSDIR)/etc/snort/local.rules; fi
	if [ -f $(ROMFSDIR)/etc/snort/drop-rules/local.rules ]; then rm -f $(ROMFSDIR)/etc/snort/drop-rules/local.rules; fi
	$(ROMFSINST) etc/classification.config /etc/snort/classification.config
	$(ROMFSINST) etc/reference.config /etc/snort/reference.config
	$(ROMFSINST) etc/unicode.map /etc/snort/unicode.map
