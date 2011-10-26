
LTC=libtomcrypt/libtomcrypt.a
LTM=libtommath/libtommath.a

OBJS=dbutil.o session.o packet.o algo.o buffer.o kex.o dss.o bignum.o \
		signkey.o rsa.o random.o service.o auth.o authpasswd.o channel.o \
		chansession.o queue.o sshpty.o termcodes.o authpubkey.o runopts.o \
		loginrec.o atomicio.o x11fwd.o agentfwd.o localtcpfwd.o compat.o \
		remotetcpfwd.o

DROPBEAROBJS=main.o

DROPBEARKEYOBJS=dropbearkey.o gendss.o genrsa.o

CONVERTOBJS=dropbearconvert.o keyimport.o

SCPOBJS=scp.o progressmeter.o atomicio.o scpmisc.o

HEADERS=options.h dbutil.h session.h packet.h algo.h ssh.h buffer.h kex.h \
		dss.h bignum.h signkey.h rsa.h random.h service.h auth.h authpasswd.h \
		debug.h channel.h chansession.h debug.h config.h queue.h sshpty.h \
		termcodes.h gendss.h genrsa.h authpubkey.h runopts.h includes.h \
		loginrec.h atomicio.h x11fwd.h agentfwd.h localtcpfwd.h compat.h \
		remotetcpfwd.h

ALLOBJS=$(OBJS) $(DROPBEARKEYOBJS) $(DROPBEAROBJS)

prefix=/
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin

INSTALL=install
CFLAGS += -Ilibtomcrypt

LIBS=$(LTC) $(LTM) -lutil  -lcrypt

# these are exported so that libtomcrypt's makefile will use them
# export CC
export CFLAGS
# export LD
# export RANLIB AR STRIP

# all: dropbear dropbearkey dropbearconvert
all: dropbearkey-host static
	@echo
	@echo Run \"make strip\" if you want stripped binaries,
	@echo or \"make install\" to install to ${prefix}

romfs:
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /bin/staticdropbear
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /etc/dropbear_dss_host_key
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR /etc/dropbear_rsa_host_key
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR \
		-a "ssh     stream tcp nowait root /bin/staticdropbear -i" /etc/inetd.conf

dropbearkey-host:
	@if [ ! -f dropbearkey-host ]; then \
		make -f Makefile.host dropbearkey-host ; \
		export CC="$(CC) $(CFLAGS)"; \
		export LDFLAGS="$(LDFLAGS)"; \
		export LIBS="$(LDLIBS)"; \
		sh configure $(CONFIGURE_OPTS) --prefix= \
				--disable-zlib --disable-wtmp \
				--disable-wtmpx --disable-syslog --disable-shadow \
				--disable-lastlog --disable-utmp --disable-utmpx ; \
	fi
	./dropbearkey-host -t rsa -f dropbear_rsa_host_key
	./dropbearkey-host -t dss -f dropbear_dss_host_key
	
strip: all
	-$(STRIP) dropbear
	-$(STRIP) dropbearkey
	-$(STRIP) dropbearconvert

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(sbindir)
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 dropbear $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 dropbearkey $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 dropbearconvert $(DESTDIR)$(bindir)
	# chown might fail, so do it separately to the install
	-chown root $(DESTDIR)$(sbindir)/dropbear
	-chgrp 0 $(DESTDIR)$(sbindir)/dropbear
	-chown root $(DESTDIR)$(bindir)/dropbearkey
	-chgrp 0 $(DESTDIR)$(bindir)/dropbearkey
	-chown root $(DESTDIR)$(bindir)/dropbearconvert
	-chgrp 0 $(DESTDIR)$(bindir)/dropbearconvert

strip-static: static
	-$(STRIP) staticdropbear
	-$(STRIP) staticdropbear
	-$(STRIP) staticdropbear

install-static: static
	$(INSTALL) -d -m 755 $(DESTDIR)$(sbindir)
	$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 staticdropbear $(DESTDIR)$(sbindir)/dropbear
	$(INSTALL) -m 755 staticdropbearkey $(DESTDIR)$(bindir)/dropbearkey
	$(INSTALL) -m 755 staticdropbearconvert $(DESTDIR)$(bindir)/dropbearconvert
	# chown might fail, so do it separately to the install
	-chown root $(DESTDIR)$(sbindir)/dropbear
	-chgrp 0 $(DESTDIR)$(sbindir)/dropbear
	-chown root $(DESTDIR)$(bindir)/dropbearkey
	-chgrp 0 $(DESTDIR)$(bindir)/dropbearkey
	-chown root $(DESTDIR)$(bindir)/dropbearconvert
	-chgrp 0 $(DESTDIR)$(bindir)/dropbearconvert

static: dropbear-static dropbearkey-static dropbearconvert-static

$(ALLOBJS): $(HEADERS) Makefile

dropbear: $(DROPBEAROBJS) $(OBJS) $(HEADERS) Makefile $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o dropbear $(DROPBEAROBJS) $(OBJS) $(LIBS) $(LDLIBS)

dropbear-static: $(DROPBEAROBJS) $(OBJS) $(HEADERS) Makefile  $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o staticdropbear $(DROPBEAROBJS) $(OBJS) $(LIBS) $(LDLIBS) -static

dropbearkey: $(OBJS) $(HEADERS) Makefile $(DROPBEARKEYOBJS) $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o dropbearkey $(DROPBEARKEYOBJS) \
		$(OBJS) $(LIBS) $(LDLIBS)

dropbearkey-static: $(OBJS) $(HEADERS) Makefile $(DROPBEARKEYOBJS) $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o staticdropbearkey $(DROPBEARKEYOBJS) \
		$(OBJS) $(LIBS) $(LDLIBS) -static

dropbearconvert: $(OBJS) $(HEADERS) Makefile $(CONVERTOBJS) $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o dropbearconvert $(CONVERTOBJS) $(OBJS) $(LIBS) $(LDLIBS)

dropbearconvert-static: $(OBJS) $(HEADERS) Makefile $(CONVERTOBJS) $(LTC) $(LTM)
	$(CC) $(LDFLAGS) -o staticdropbearconvert $(CONVERTOBJS) $(OBJS) $(LIBS) \
		$(LDLIBS) -static

multi: dropbearmulti

dropbearmulti: $(HEADERS) $(OBJS) $(LTC) $(LTM) $(CONVERTOBJS) \
				$(DROPBEARKEYOBJS) $(DROPBEAROBJS) dbmulti.o
	$(CC) $(LDFLAGS) -o dropbearmulti $(OBJS) $(LTM) $(LTM) $(CONVERTOBJS) \
			$(DROPBEARKEYOBJS) $(DROPBEAROBJS) dbmulti.o $(LIBS) $(LDLIBS)
	@echo "You should now create symlinks to the programs you have included"
	@echo "ie 'ln -s dropbearmulti dropbear'"

dropbearmultistatic: $(HEADERS) $(OBJS) $(LTC) $(LTM) $(CONVERTOBJS) \
						$(DROPBEARKEYOBJS) $(DROPBEAROBJS) dbmulti.o
	$(CC) $(LDFLAGS) -o staticdropbearmulti $(OBJS) $(LTM) $(LTM) \
			$(CONVERTOBJS) $(DROPBEARKEYOBJS) $(DROPBEAROBJS) \
			dbmulti.o $(LIBS) $(LDLIBS) -static
	@echo "You should now create symlinks to the programs you have included"
	@echo "ie 'ln -s dropbearmultistatic dropbear'"

stripmulti: dropbearmulti
	-$(STRIP) dropbearmulti


scp: $(SCPOBJS) Makefile
	$(CC) $(LDFLAGS) -o $@ $(SCPOBJS)

# gnumake before 3.80 is broken. So this is uglyish
scp-progress: atomicio.o scpmisc.o $(HEADERS) Makefile
	-rm scp.o progressmeter.o
	$(MAKE) CFLAGS="$(CFLAGS) -DPROGRESS_METER" scp.o progressmeter.o
	$(CC) $(LDFLAGS) -o $@ $(SCPOBJS)

scpstatic: $(SCPOBJS) $(HEADERS) Makefile
	$(CC) $(LDFLAGS) -o $@ $(SCPOBJS) -static

$(LTC): $(HEADERS)
	cd libtomcrypt && $(MAKE) clean && $(MAKE)

$(LTM): $(HEADERS)
	cd libtommath && $(MAKE)

ltc-clean:
	cd libtomcrypt && $(MAKE) clean

ltm-clean:
	cd libtommath && $(MAKE) clean

sizes: dropbear
	objdump -t dropbear|grep ".text"|cut -d "." -f 2|sort -rn

clean: ltc-clean ltm-clean
	-rm -f dropbear dropbear dropbearkey staticdropbear staticdropbearkey
	-rm -f dropbearconvert staticdropbearconvert scp scp-progress scpstatic
	-rm -f dropbearmulti dropbearmultistatic
	-rm -f dropbearkey-host dropbear_dss_host_key dropbear_rsa_host_key
	-rm -f *.o *.da *.bb *.bbg *.prof *.gdb

distclean: clean tidy
	-rm -f Makefile config.h

tidy:
	-rm -f *~ *.gcov */*~
