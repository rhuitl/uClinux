# uCLinux specific Makefile

CONIGURE_FOPTS := --disable-largefile --disable-zlib --disable-syslog \
                  --disable-lastlog --disable-utmp --disable-wtmp
# LDFLAGS +=

all: Makefile
	$(MAKE) -f Makefile PROGRAMS="dropbear" STATIC=1

Makefile: dropbear_rsa_host_key dropbear_dss_host_key
	@chmod u+x configure
	sh configure $(CONFIGURE_OPTS)

makefile:
	@echo dummy target to avoid % catching us

clean:
	-$(MAKE) -f Makefile distclean
	-$(MAKE) -f Makefile.host distclean
	-rm -f dropbearkey-host dropbear_rsa_host_key dropbear_dss_host_key

dropbear_rsa_host_key dropbear_dss_host_key:
	make -f Makefile clean ; \
	CC=gcc LD=ld CFLAGS= LDFLAGS= ./configure && \
	make -f Makefile.host dropbearkey
	cp dropbearkey dropbearkey-host
	make -f Makefile.host clean
	./dropbearkey-host -t rsa -f dropbear_rsa_host_key
	./dropbearkey-host -t dss -f dropbear_dss_host_key

romfs:
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /bin/dropbear
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /etc/dropbear_dss_host_key
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /etc/dropbear_rsa_host_key
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR \
		-a "ssh     stream tcp nowait root /bin/dropbear -i" /etc/inetd.conf

%: Makefile
	$(MAKE) -f Makefile $@
