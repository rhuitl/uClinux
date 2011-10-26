#
# uClinux-dist makefile for openssh
# davidm@snapgear.com
#

CONFOPTS =
CONFOPTS += --prefix=
CONFOPTS += --sbindir=/bin
CONFOPTS += --disable-etc-default-login

ifdef ROOTDIR
ifdef LIBCDIR
-include $(ROOTDIR)/$(LIBCDIR)/.config
endif
endif
ifdef HAS_SHADOW
CONFOPTS += --with-shadow
else
CONFOPTS += --without-shadow
endif

# CONFOPTS += --disable-shared
# CONFOPTS += --disable-static

CONFOPTS += --without-stackprotect

ifdef CONFIG_USER_FLATFSD_FLATFSD
CONFOPTS += --sysconfdir=/etc/config
else
CONFOPTS += --sysconfdir=/etc
endif

# If we're building with libpam, we add this capability to ssh
ifdef CONFIG_LIB_LIBPAM
NEED_LIB_PAM := y
endif
ifdef CONFIG_LIB_LIBPAM_FORCE
NEED_LIB_PAM := y
endif
ifeq ($(NEED_LIB_PAM),y)
CONFOPTS += --with-pam
endif

FLTFLAGS += -s 65536
ifdef CONFIG_PROP_SSH_SECURITY_COUNT
CFLAGS += -DSECURITY_COUNTS
endif
ifeq ($(CONFIG_USER_SSH_SSHD),y)
CFLAGS += -DINCLUDE_SSHD
endif
ifeq ($(CONFIG_USER_SSH_SSH),y)
CFLAGS += -DINCLUDE_SSH
endif


all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_SSH_SSH build/ssh /bin/ssh
	$(ROMFSINST) -e CONFIG_USER_SSH_SSH /etc/default/ssh_config
	: $(ROMFSINST) -e CONFIG_USER_SSH_SSH -p 700 -d /.ssh
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHD build/sshd /bin/sshd
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHKEYGEN build/ssh-keygen /bin/ssh-keygen
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHKEYGEN build/gen-keys /bin/gen-keys
	$(ROMFSINST) -e CONFIG_USER_SSH_SCP build/scp /bin/scp
	$(ROMFSINST) -e CONFIG_USER_SSH_SFTP build/sftp /bin/sftp
	$(ROMFSINST) -d -e CONFIG_USER_SSH_SFTP_SERVER build/sftp-server /usr/libexec/sftp-server
	$(ROMFSINST) -d -e CONFIG_USER_SSH_SSH_KEYSIGN build/ssh-keysign /usr/libexec/ssh-keysign
ifndef CONFIG_PROP_CONFIG_LIBCONFIG
	##
	# Add the appropriate stuff to the start files.
	#
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHD /etc/default/sshd_config
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHKEYGEN \
		-a "gen-keys &" /etc/default/start
	$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)$(CONFIG_USER_SSH_SSH)" \
		-A "root:" -a "root:abTxyM1SdxNko:0:0:Root:/:/bin/sh" \
		/etc/default/passwd
	$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)$(CONFIG_USER_SSH_SSH)" \
		-A "root:" -a "root:x:0:root" /etc/default/group
	$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)" \
		-A "sshd:" -a "sshd:x:100:65534::/var/run/sshd:/bin/false" \
		/etc/default/passwd
	$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)" \
		-A "nobody:" -a "nobody:x:65534:" /etc/default/group
endif
	$(ROMFSINST) -e CONFIG_USER_SSH_SSHD \
		-a "#ssh details are now in /etc/config/inetd.conf" /etc/inetd.conf
	##
	# Optionally add the startup stuff to the /etc/default-static dir.
	#
	if [ -d $(ROMFSDIR)/etc/default-static ] ; then \
		$(ROMFSINST) -e CONFIG_USER_SSH_SSHKEYGEN \
			-a "gen-keys &" /etc/default-static/start ; \
		$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)$(CONFIG_USER_SSH_SSH)" \
			-a "root:abTxyM1SdxNko:0:0:Root:/:/bin/sh" -A "root:"\
			/etc/default-static/passwd ; \
		$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)$(CONFIG_USER_SSH_SSH)" \
			-A "root:" -a "root:x:0:root" /etc/default-static/group ; \
		$(ROMFSINST) -e CONFIG_USER_SSH_SSH /etc/default-static/ssh_config ; \
		$(ROMFSINST) -e CONFIG_USER_SSH_SSHD /etc/default-static/sshd_config ; \
		$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)" \
			-A "sshd:" -a "sshd:x:100:65534::/var/run/sshd:/bin/false" \
			/etc/default-static/passwd ; \
		$(ROMFSINST) -o "$(CONFIG_USER_SSH_SSHD)" \
			-A "nobody:" -a "nobody:x:65534:" /etc/default-static/group ;\
	fi


