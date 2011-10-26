CONFOPTS :=	--enable-dependency-tracking \
		--disable-largefile \
		--enable-http \
		--enable-ftp \
		--enable-gopher \
		--enable-file \
		--disable-ldap \
		--enable-static\
		--disable-shared\ 
		--enable-dict \
		--enable-telnet \
		--enable-manual \
		--enable-ipv6 \
		--enable-nonblocking \
		--disable-thread \
		--disable-ares \
		--enable-verbose \
		--disable-sspi \
		--enable-debug \
		--enable-crypto-auth \
		--enable-cookies \
		--with-random=/dev/urandom \
		--with-ssl=$(ROOTDIR)/lib/libssl \
		--with-zlib=$(ROOTDIR)/lib/zlib \
		--with-libidn=$(ROOTDIR)/lib/libidn
URL := http://curl.haxx.se/download/curl-7.21.1.tar.bz2
AUTOMAKE_ROMFS = curl_romfs
include $(ROOTDIR)/tools/automake.inc

curl_romfs:
	$(ROMFSINST) build/curl-7.21.1-install/lib/libcurl.so /lib/libcurl.so
