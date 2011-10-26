ifdef CONFIG_USER_NTPD_NTPDATE
NTPDATE := with
else
NTPDATE := without
endif

ifdef CONFIG_USER_NTPD_NTPDC
NTPDC := with
else
NTPDC := without
endif

ifdef CONFIG_USER_NTPD_NTPQ
NTPQ := with
else
NTPQ := without
endif

CONFOPTIONS=								   \
	--disable-debugging	\
	--disable-HOPFSERIAL --disable-HOPFPCI --disable-BANCOMM           \
	--disable-GPSVME --disable-SHM --disable-all-clocks                \
	--disable-ACTS --disable-ARBITER --disable-ARCRON-MSF              \
	--disable-ATOM --disable-AS2201 --disable-CHU --disable-AUDIO-CHU  \
	--disable-DATUM --disable-FG --disable-HEATH --disable-HPGPS       \
	--disable-IRIG --disable-JJY --disable-LEITCH                      \
	--disable-LOCAL-CLOCK --disable-MSFEES --disable-MX4200            \
	--disable-NMEA --disable-ONCORE --disable-PALISADE --disable-PST   \
	--disable-JUPITER --disable-PTBACTS --disable-TPRO --disable-TRAK  \
	--disable-CHRONOLOG --disable-DUMBCLOCK --disable-PCF              \
	--disable-SPECTRACOM --disable-TRUETIME --disable-ULINK            \
	--disable-WWV --disable-USNO --disable-parse-clocks                \
	--disable-COMPUTIME --disable-DCF7000 --disable-HOPF6021           \
	--disable-MEINBERG --disable-RAWDCF --disable-RCC8000              \
	--disable-SCHMID --disable-TRIMTAIP --disable-TRIMTSIP             \
	--disable-WHARTON --disable-VARITEXT --disable-kmem                \
	--without-openssl-libdir --without-openssl-incdir --without-crypto \
	--without-electricfence --without-sntp --$(NTPDATE)-ntpdate \
	--$(NTPDC)-ntpdc --$(NTPQ)-ntpq


all: builddir/configured
	$(MAKE) -C builddir CFLAGS='$(CFLAGS) -DCONFIG_FILE=\"/etc/config/ntp.conf\"'

romfs:
	$(ROMFSINST) -e CONFIG_USER_NTPD_NTPD builddir/ntpd/ntpd /bin/ntpd
	$(ROMFSINST) -e CONFIG_USER_NTPD_NTPDATE builddir/ntpdate/ntpdate /bin/ntpdate
	$(ROMFSINST) -e CONFIG_USER_NTPD_NTPDC builddir/ntpdc/ntpdc /bin/ntpdc
	$(ROMFSINST) -e CONFIG_USER_NTPD_NTPQ builddir/ntpq/ntpq /bin/ntpq


builddir/configured: makefile
	rm -rf builddir
	mkdir builddir
	( \
		cd builddir; \
		CC="$(CC) $(CFLAGS)" LDFLAGS="$(LDFLAGS)" LIBS="$(LDLIBS)" \
		MISSING="true" \
			../configure --prefix= \
			$(CONFIGURE_OPTS) $(CONFOPTIONS) \
	)
	touch builddir/configured

clean:
	rm -rf builddir
