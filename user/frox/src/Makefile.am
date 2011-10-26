sbin_PROGRAMS = frox
frox_SOURCES = configs.h configs.c data.c main.c misc.c control.c ftp-cmds.c common.h control.h data.h ftp-cmds.h cache.h ccp.h misc.h ntp.h os.h vscan.h
BUILT_SOURCES = configs.c configs.h
frox_LDADD = @VSCAN_STUFF@ @CACHE_STUFF@ @HCACHE_STUFF@ @LCACHE_STUFF@ \
@NTP_STUFF@ @CCP_STUFF@ @TD_STUFF@ @SSL_STUFF@ @HOST_FILE@ -lsstr \
@LIBSSL@ @LIBIPTC@ @ARCH_LIBS@
frox_DEPENDENCIES = @VSCAN_STUFF@ @CACHE_STUFF@ @HCACHE_STUFF@ @LCACHE_STUFF@ \
@NTP_STUFF@ @CCP_STUFF@ @TD_STUFF@ @SSL_STUFF@ @HOST_FILE@
EXTRA_frox_SOURCES = cache.c ntp.c httpcache.c localcache.c cachemgr.c vscan.c linux.c bsd.c ccp.c transdata.c transdata.h ssl.c ssl.h
EXTRA_DIST = configen.pl configs.c.in configs.h.in configs.tpl frox.conf

frox_LDFLAGS = -L../lib

configs.h: configs.h.in configs.tpl
	./configen.pl configs.tpl configs.h.in configs.h

configs.c: configs.c.in configs.tpl
	./configen.pl configs.tpl configs.c.in configs.c

distclean-local:
	rm -f configs.c configs.h
