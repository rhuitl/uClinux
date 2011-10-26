
CONFOPTS :=	--enable-ssl --enable-virus-scan		\
		--disable-ntp					\
		--enable-configfile=/etc/config/frox.conf

LDFLAGS += -Wl,--allow-multiple-definition

all: Makefile
	$(MAKE) -f Makefile

Makefile: makefile
	@chmod u+x configure
	sh configure $(CONFIGURE_OPTS) $(CONFOPTS)

makefile:
	@echo dummy target to avoid % catching us

clean:
	$(MAKE) -f Makefile distclean

romfs:
	$(ROMFSINST) src/frox /bin/frox
	$(ROMFSINST) -d src/frox.conf /etc/clamav/frox.conf

%: Makefile
	$(MAKE) -f Makefile $@
