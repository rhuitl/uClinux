CONFOPTS :=--bindir=/bin --datadir=/etc 
CONFOPTS += --enable-dependency-tracking --disable-largefile
CONFOPTS += --disable-man --disable-nls
CONFOPTS += --without-selinux --without-audit --without-skey
CONFOPTS += --without-libcrack

ifdef CONFIG_USER_SHADOW_PAM
CONFOPTS += --with-libpam	# This autodetcts properly but what the heck
endif
ifdef CONFIG_USER_SHADOW_SHAREDLIB
CONFOPTS += --enable-shared
EXECPTH := build/src/.libs
else
EXECPTH := build/src
endif

# Have to specify the correct paths to various files
ifdef CONFIG_USER_FLATFSD_FLATFSD
CFLAGS += -DPASSWD_FILE='"/etc/config/passwd"'
CFLAGS += -DGROUP_FILE='"/etc/config/group"'
CFLAGS += -DSHADOW_FILE='"/etc/config/shadow"'
CFLAGS += -DSGROUP_FILE='"/etc/config/gshadow"'
CFLAGS += -DLOGINDEFS='"/etc/config/login.defs"'
endif

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	chmod a+x configure
	(cd build; ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build


# We place these programs in their correct places.  See build/src/Makefile
# for the correct locations.
BINPROGS :=	login su

SBINPROGS :=	sulogin

USRBINPROGS :=	chage chfn chsh expiry faillog gpasswd groups id
USRBINPROGS +=	lastlog newgrp passwd

USRSBINPROGS := chpasswd groupadd groupdel groupmod grpck grpconv
USRSBINPROGS += grpunconv logoutd newusers nologin pwck pwconv pwunconv
USRSBINPROGS += useradd userdel usermod vipw

romfs:
ifdef CONFIG_USER_SHADOW_SHAREDLIB
	$(ROMFSINST) build/lib/.libs/libshadow.so.0.0.0 /lib/libshadow.so.0.0.0
	$(ROMFSINST) -s libshadow.so.0.0.0 /lib/libshadow.so.0
	$(ROMFSINST) -s libshadow.so.0.0.0 /lib/libshadow.so
endif
	@for f in $(BINPROGS);						\
	do								\
		ev="CONFIG_USER_SHADOW_`echo $$f | tr a-z A-Z`";	\
		$(ROMFSINST) -e "$$ev" $(EXECPTH)/$$f /bin/$$f;		\
	done
	@for f in $(SBINPROGS);						\
	do								\
		ev="CONFIG_USER_SHADOW_`echo $$f | tr a-z A-Z`";	\
		$(ROMFSINST) -e "$$ev" $(EXECPTH)/$$f /sbin/$$f;	\
	done
	@for f in $(USRBINPROGS);					\
	do								\
		ev="CONFIG_USER_SHADOW_`echo $$f | tr a-z A-Z`";	\
		$(ROMFSINST) -e "$$ev" $(EXECPTH)/$$f /usr/bin/$$f;	\
	done
	@for f in $(USRSBINPROGS);					\
	do								\
		ev="CONFIG_USER_SHADOW_`echo $$f | tr a-z A-Z`";	\
		$(ROMFSINST) -e "$$ev" $(EXECPTH)/$$f /usr/sbin/$$f;	\
	done
