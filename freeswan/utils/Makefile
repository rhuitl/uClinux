# utilities build and install
# Copyright (C) 1998-2001  Henry Spencer.
# 
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# RCSID $Id: Makefile,v 1.106 2002/04/01 20:05:27 mcr Exp $



include ../Makefile.inc
include ../Makefile.ver



PUBS=ipsec
BINS=_copyright ranbits rsasigkey
SCRIPTS=auto barf look manual newhostkey showdefaults showhostkey send-pr
INTERNALS=_include _confread _keycensor _secretcensor _updown _updown.dhcp \
	_realsetup _startklips _plutorun _plutoload
PRIVS=$(PUBS) $(SCRIPTS) $(INTERNALS) $(BINS)
LIBFILES=ipsec_pr.template
GENDFILES=secrets.eg conf.eg
GENDSCRIPTS=ipsec send-pr 
LOCALS=
PLAIN_MANS=ipsec.8
IPSEC_CMANS=auto.8 barf.8 manual.8 newhostkey.8 ranbits.8 rsasigkey.8 setup.8 \
	showdefaults.8 showhostkey.8 send-pr.8
MANS=$(PLAIN_MANS) $(IPSEC_CMANS)
CFLAGS=-I../lib $(USERCOMPILE)
LIB=../lib/libfreeswan.a
PUB=--mode=644
PRIV=--mode=600
RSAKEYBITS=2192
FMANDIR=$(MANTREE)/man5
CMANDIR=$(MANTREE)/man8
.PHONY:	all newsecrets install setup4 clean checkprograms



all:	$(PUBS) $(PRIVS) $(GENDFILES) $(LOCALS)
programs: all

ranbits:	ranbits.o
	$(CC) $(CFLAGS) ranbits.o $(LIB) -o $@

rsasigkey:	rsasigkey.o
	$(CC) $(CFLAGS) rsasigkey.o $(LIB) -lgmp -o $@

_copyright:	_copyright.o
	$(CC) $(CFLAGS) _copyright.o $(LIB) -o $@

ipsec:	ipsec.in ../Makefile.ver
	sed -e "s/xxx/$(IPSECVERSION)/" -e "s:@IPSEC_DIR@:$(FINALBINDIR):" \
		-e "s:@IPSEC_CONFS@:$(FINALCONFDIR):" ipsec.in >$@
	chmod +x $@

send-pr: send-pr.sh
	sed "s:@IPSEC_DIR@:$(FINALBINDIR):" send-pr.sh >$@
	chmod +x $@

send-pr.8: send-pr.man
	sed "s/xVERSIONx/$(IPSECVERSION)/" send-pr.man | sed "s:@IPSEC_DIR@:$(FINALBINDIR):" >$@

# generate RSA private key... if, and only if, /etc/ipsec.secrets does
# not already exist
BLURB=-- not filled in because ipsec.secrets existed at build time --
secrets.eg:	secrets.proto ranbits rsasigkey
	rm -f $@
	umask 077 ; ( \
		sed '/yyy/,$$d' secrets.proto ; \
		if test ! -f $(CONFDIR)/ipsec.secrets ; \
		then ./rsasigkey --verbose $(RSAKEYBITS) ; \
		else echo "	# $(BLURB)" ; \
		fi ; \
		sed '1,/yyy/d' secrets.proto ; \
	) | egrep -v RCSID >$@

# force full secrets-file build
newsecrets:
	rm -f secrets.eg
	$(MAKE) secrets.eg CONFDIR=.

conf.eg:	conf.proto ranbits randomize
	rm -f $@
	./randomize conf.proto | egrep -v RCSI >$@

INSTMAN=$(INSTALL) $(INSTMANFLAGS)
INSTCONF=$(INSTALL) $(INSTCONFFLAGS)
install:	$(PUBS) $(PRIVS) $(MANS) $(GENDFILES) $(IPSEC_CMANS) 
	mkdir -p $(PUBDIR) $(BINDIR) $(FMANDIR) $(CMANDIR) $(CONFDIR)
	$(INSTALL) $(INSTBINFLAGS) $(PUBS) $(PUBDIR)
	$(INSTALL) $(INSTBINFLAGS) $(PRIVS) $(BINDIR)
	$(INSTALL) $(INSTCONFFLAGS) $(PUB) $(LIBFILES) $(BINDIR)
	$(INSTALL) $(INSTMANFLAGS) $(PUB) ipsec.conf.5 $(FMANDIR)
	$(INSTALL) $(INSTMANFLAGS) $(PUB) $(PLAIN_MANS) $(CMANDIR)
	for f in $(IPSEC_CMANS) ; \
	do \
		$(INSTMAN) $(PUB) $$f $(CMANDIR)/ipsec_$$f || exit 1 ; \
		./manlink $(CMANDIR) ipsec_$$f ; \
	done
	test -f $(CONFDIR)/ipsec.secrets || \
		$(INSTCONF) $(PRIV) secrets.eg $(CONFDIR)/ipsec.secrets
	test -f $(CONFDIR)/ipsec.conf || \
		$(INSTCONF) $(PUB) conf.eg $(CONFDIR)/ipsec.conf
	# main copy must go in RCDIR, BINDIR may not be mounted at boot time
	mkdir -p $(RCDIR)
	$(INSTALL) $(INSTBINFLAGS) setup $(RCDIR)/ipsec
	rm -f $(BINDIR)/setup
	ln -s $(FINALRCDIR)/ipsec $(BINDIR)/setup
	PATH=/sbin:/usr/sbin:$$PATH ; export PATH ; \
	if test " $(DESTDIR)" != " " ; \
	then : do nothing ; \
	elif which chkconfig >/dev/null 2>&1 ; \
	then chkconfig --add ipsec ; \
	else $(MAKE) setup4 ; \
	fi

setup4:	$(RCDIR)/ipsec
	# fallback rc install -- on in run states 2345, off in 016, with
	# priorities matching those in setup's chkconfig line
	-cd $(RCDIR)/../rc0.d ; ln -s ../init.d/ipsec K68ipsec
	-cd $(RCDIR)/../rc1.d ; ln -s ../init.d/ipsec K68ipsec
	-cd $(RCDIR)/../rc2.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc3.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc4.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc5.d ; ln -s ../init.d/ipsec S47ipsec
	-cd $(RCDIR)/../rc6.d ; ln -s ../init.d/ipsec K68ipsec

clean:
	rm -f *.o $(BINS) $(GENDFILES) $(GENDSCRIPTS) $(LOCALS)

checkprograms:
