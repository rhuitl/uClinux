
srcdir = $(ROOTDIR)/freeswan/utils

# pathnames, subject to overrides from main Makefile
FLTFLAGS+= 	-s 4096
PUBS=ipsec
BINS=ranbits rsasigkey
SCRIPTS=$(srcdir)/barf $(srcdir)/manual $(srcdir)/auto $(srcdir)/look \
		$(srcdir)/showdefaults $(srcdir)/showhostkey
INTERNALS=$(srcdir)/_include $(srcdir)/_confread $(srcdir)/_keycensor \
			$(srcdir)/_secretcensor $(srcdir)/_updown
PRIVS=$(PUBS) $(SCRIPTS) $(INTERNALS) $(BINS)
# GENDFILES=secrets.eg conf.eg
PERMINDEX=html2four four2perm
LOCALS= #man_xref $(PERMINDEX)
CFLAGS += -I$(srcdir)/../lib
LIB    = ../lib/libfreeswan.a
LIBGMP = -lgmp
SECRETBITS=256
RSAKEYBITS=2048

vpath %.c $(srcdir)

SHELL=/bin/sh

all:	$(PUBS) $(PRIVS) $(GENDFILES) $(LOCALS)

permindex:	$(PERMINDEX)

ranbits:	ranbits.o
	$(CC) $(LDFLAGS) ranbits.o $(LIB) -o $@ $(LDLIBS)

rsasigkey:	rsasigkey.o
	$(CC) $(LDFLAGS) rsasigkey.o $(LIB) -o $@ $(LIBGMP) $(LDLIBS)

romfs:
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_UTILS_RANBITS /bin/ranbits
	$(ROMFSINST) -e CONFIG_USER_FREESWAN_UTILS_RSASIGKEY /bin/rsasigkey

man_xref:	man_xref.o
	$(CC) $(LDFLAGS) man_xref.o $(LIB) -o $@ $(LDLIBS)

html2four:	html2four.o
	$(CC) $(LDFLAGS) html2four.o $(LIB) -o $@ $(LDLIBS)

four2perm:	four2perm.o
	$(CC) $(LDFLAGS) four2perm.o $(LIB) -o $@ $(LDLIBS)

ipsec:	$(srcdir)/ipsec.in
	VER=`sed -n '/"/s/^[^"]*"//p' $(srcdir)/../version.c | sed 's/".*//'` ; \
	sed "s/xxx/$$VER/" $< | sed "s:@IPSECDIR@:$(REALPRIVDIR):" >$@
	chmod +x $@

# generate sample secret (obfuscating it so that people don't get confused
# about whether it is a string or a hex number) and RSA private key... if,
# and only if, /etc/ipsec.secrets does not already exist
BLURB=do   make newsecrets   if you want this filled in
secrets.eg:	$(srcdir)/secrets.proto ranbits rsasigkey
	rm -f $@
	umask 077 ; ( \
		sed '/yyy/,$$d' $(srcdir)/secrets.proto | \
			sed "s/xxx/` \
				if test ! -f $(CONFDIR)/ipsec.secrets ; \
				then ./ranbits $(SECRETBITS) | \
					tr '0-9a-f_' 'j-n1-5R-Wu' ; \
				else echo '$(BLURB)' ; \
				fi `/" ; \
		if test ! -f $(CONFDIR)/ipsec.secrets ; \
		then ./rsasigkey --verbose $(RSAKEYBITS) ; \
		else echo "	# $(BLURB)" ; \
		fi ; \
		sed '1,/yyy/d' $(srcdir)/secrets.proto ; \
	) | egrep -v RCSID >$@

# force full secrets-file build
newsecrets:
	rm -f secrets.eg
	$(MAKE) secrets.eg CONFDIR=.

conf.eg:	$(srcdir)/conf.proto ranbits randomize
	rm -f $@
	./randomize $(srcdir)/conf.proto | egrep -v RCSI >$@

clean:
	rm -f *.gdb *.elf *.o $(BINS) $(GENDFILES) $(LOCALS) $(PUBS)
