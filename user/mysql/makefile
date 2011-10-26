
CONFOPTS :=	-C --prefix=					\
		--enable-dependency-tracking				\
		--with-named-thread-libs=-lpthread \
		--without-readline --disable-shared			\
		--with-mysql=$(ROOTDIR)/lib/libmysqlclient		\
		--with-pic
MY_EXTRA_CFLAGS := -DHAVE_GETHOSTBYNAME_R_GLIBC2_STYLE=1


all: configured
	$(MAKE) -f Makefile

configured: makefile
	@chmod u+x configure
	@rm -f configured
	sh ./configure $(CONFIGURE_OPTS) $(CONFOPTS)
	@touch configured

clean:
	-$(MAKE) -f Makefile clean
	rm -f config.cache
	rm -rf configured
	rm -rf autom4te.cache config.cache config.h config.log config.status
	rm -rf libtool stamp-h1
	-(find . -name Makefile | xargs rm -f)
	-(find . -name .deps | xargs rm -rf)

romfs:
	-echo "nothing for romfs"

%:
	$(MAKE) -f Makefile $@
