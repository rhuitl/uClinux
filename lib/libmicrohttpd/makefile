# uCLinux specific Makefile

CONFOPTS := --disable-postprocessor --disable-dauth --disable-shared

LDFLAGS += -Wl,--allow-multiple-definition

all: Makefile
	$(MAKE) -f Makefile

Makefile: makefile
	./bootstrap
	sh configure $(CONFIGURE_OPTS) $(CONFOPTS)

makefile:
	@echo dummy target to avoid % catching us

clean:
	$(MAKE) -f Makefile distclean

romfs:
	@echo Nothing to install for romfs
#	$(ROMFSINST) src/foo /bin/foo
#	$(ROMFSINST) -d src/foo.conf /etc/foo.conf

%: Makefile
	$(MAKE) -f Makefile $@
