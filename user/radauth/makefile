CONFOPTS :=	

all: configured
	$(MAKE) -f Makefile

configured: makefile
	sh configure $(CONFIGURE_OPTS) $(CONFOPTS)
	@touch $@

clean:
	[ ! -f Makefile ] || $(MAKE) -f Makefile clean
	rm -f configured config.* Makefile

romfs:
	$(ROMFSINST) /bin/radauth
