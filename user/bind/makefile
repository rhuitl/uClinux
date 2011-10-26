CONFOPTIONS=--with-randomdev=/dev/random \
	    --enable-shared \
	    --sysconfdir=/etc/config \
	    --with-libtool

all: builddir
	$(MAKE) -C builddir

romfs:
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/check/.libs/named-checkconf /bin/named-checkconf
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/check/.libs/named-checkzone /bin/named-checkzone
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/dig/.libs/dig /bin/dig
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/dig/.libs/host /bin/host
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/dig/.libs/nslookup /bin/nslookup
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/dnssec/.libs/dnssec-keygen /bin/dnssec-keygen
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/dnssec/.libs/dnssec-signzone /bin/dnssec-signzone
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/named/.libs/named /bin/named
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND -l /bin/named /bin/lwresd
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/nsupdate/.libs/nsupdate /bin/nsupdate
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/rndc/.libs/rndc /bin/rndc
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/bin/rndc/.libs/rndc-confgen /bin/rndc-confgen
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/isc/.libs/libisc.so.32.0.3 /lib/libisc.so.32
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/isccc/.libs/libisccc.so.30.0.1 /lib/libisccc.so.30
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/isccfg/.libs/libisccfg.so.30.0.2 /lib/libisccfg.so.30
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/dns/.libs/libdns.so.32.1.1 /lib/libdns.so.32
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/bind9/.libs/libbind9.so.30.0.3 /lib/libbind9.so.30
	$(ROMFSINST) -e CONFIG_USER_BIND_BIND builddir/lib/lwres/.libs/liblwres.so.30.0.4 /lib/liblwres.so.30

builddir: makefile
	rm -rf builddir
	mkdir builddir
	( \
		cd builddir; \
		BUILD_CC="gcc" \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" \
		MISSING="true" \
			../configure --prefix= \
			--with-headers=$(ROOTDIR)/$(LINUXDIR)/include \
			$(CONFIGURE_OPTS) $(CONFOPTIONS) \
	)

clean:
	rm -rf builddir
