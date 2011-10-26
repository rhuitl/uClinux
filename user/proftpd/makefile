CONFOPTS=--enable-cap --prefix= --with-libraries=$(ROOTDIR)/user/proftpd/build/lib 

-include $(LIBCDIR)/.config
ifdef HAVE_SHADOW
CONFOPTS += --enable-shadow
else
CONFOPTS += --disable-shadow
endif

# If we're building with libpam, we add this capability to ssh
ifdef CONFIG_LIB_LIBPAM
NEED_LIB_PAM := y
endif
ifdef CONFIG_LIB_LIBPAM_FORCE
NEED_LIB_PAM := y
endif
ifeq ($(NEED_LIB_PAM),y)
CONFOPTS += --with-modules=mod_auth_pam
PAM_ELIBS:= -ldl
else
CONFOPTS += --disable-auth-pam
endif

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; LIBS="$(LIBS)$(PAM_ELIBS)" sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	mkdir -p build/lib/libcap
	cp lib/libcap/Makefile build/lib/libcap/
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) build/proftpd /bin/proftpd
