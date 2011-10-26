#
# build using configure

CONF_OPTS := --prefix=
CONF_OPTS += --host=i386-redhat-linux
CONF_OPTS += --target=$(CROSS_COMPILE:-=)
CONF_OPTS += --disable-fast-install
CONF_OPTS += --enable-dependency-tracking

all: Makefile
	if [ \! -e doc/man/man3 ]; then mkdir -p doc/man/man3; fi
	$(MAKE) -f Makefile
ifdef CONFIG_LIB_LIBJUDY_TESTS
	( cd test; ./Checkit )
endif

Makefile: makefile
	sh ./configure $(CONFIGURE_OPTS) $(CONFOPTS)

romfs:
	$(ROMFSINST) src/obj/.libs/libJudy.so.1.0.3 /lib/libJudy.so.1.0.3
	$(ROMFSINST) -s libJudy.so.1.0.3 /lib/libJudy.so.1
	$(ROMFSINST) -s libJudy.so.1.0.3 /lib/libJudy.so
ifdef CONFIG_LIB_LIBJUDY_TESTS
	$(ROMFSINST) test/StringCompare.c /etc/StringCompare.c
	$(ROMFSINST) test/Judy1LHCheck /bin/Judy1LHCheck
	$(ROMFSINST) test/Judy1LHTime /bin/Judy1LHTime
	$(ROMFSINST) test/SL_Hash /bin/SL_Hash
	$(ROMFSINST) test/SL_Splay /bin/SL_Splay
	$(ROMFSINST) test/SL_Redblack /bin/SL_Redblack
	$(ROMFSINST) test/SL_Judy /bin/SL_Judy
endif

clean:
	$(MAKE) -f Makefile distclean

%: Makefile
	$(MAKE) -f Makefile $@
