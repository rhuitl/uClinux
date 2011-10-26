# Pluto Makefile
# Copyright (C) 1997 Angelos D. Keromytis.
# Copyright (C) 1998-2001  D. Hugh Redelmeier
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
# RCSID $Id: Makefile,v 1.95 2002/04/02 04:08:01 mcr Exp $



include ../Makefile.inc



FMANDIR=$(MANTREE)/man5
PMANDIR=$(MANTREE)/man8

FREESWANLIBDIR=../lib
FREESWANINCLS= -I$(FREESWANLIBDIR)
FREESWANLIB=$(FREESWANLIBDIR)/libfreeswan.a
LIBDESLITE=$(FREESWANLIBDIR)/libdes.a

KLIPSD=../klips/net/ipsec

# -O on Linux makes gcc coredump when compiling sha1.c
# -Wundef is nice but RHL5.2 compiler doesn't support it
CFLAGS = -g -Wall -W -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast \
	-Wcast-qual -Wmissing-declarations -Wwrite-strings \
	-Wstrict-prototypes # -Wundef

# where to find klips headers and FreeS/WAN headers
HDRDIRS = -I$(KLIPSD) $(FREESWANINCLS)

# On non-LINUX systems, these one of these may be needed (see endian.h)
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=BIG_ENDIAN
# BYTE_ORDER = -DBIG_ENDIAN=4321 -DLITTLE_ENDIAN=1234 -DBYTE_ORDER=LITTLE_ENDIAN

# -DKLIPS enables interface to Kernel LINUX IPsec code
# -DDEBUG enables debugging code, allowing for debugging output
#    (note that output must also be selected at runtime, so it is
#    reasonable to always define this)
# -DGCC_LINT uses gcc-specific declarations to improve compile-time
#    diagnostics.
# -DLEAK_DETECTIVE enables crude code to find memory allocation leaks.
# -DDODGE_DH_MISSING_ZERO_BUG enables kludge to remain interoperable
#    with Pluto from FreeS/WAN 1.00 and before.
# -DOLD_RESOLVER.  At some point, the resolver interface changed.
#    This macro enables Pluto support for the old interface.
#    It is automatically defined, based on the value of the <resolver.h>
#    macro __RES.  We don't know the correct threshold, so you may
#    find that you must manually define this.  If so, please inform
#    us so that we can refine the threshold.

# The following are best left undefined -- each can be overridden at runtime
# if need be.
# -DPORT=n sets the default UDP port for IKE messages (otherwise 500)
# -DSHARED_SECRETS_FILE=string overrides /etc/ipsec.secrets as the
#    default name of the file containing secrets used to authenticate other
#    IKE daemons.  In the Makefile, two levels of quoting are needed:
#    -DSHARED_SECRETS_FILE='"/etc/ipsec.secrets"'
# -DDEFAULT_CTLBASE=string overrides /var/run/pluto as default directory
#    and basename for pluto's lockfile (.pid) and control socket (.ctl).
#    Double quoting may be needed.

DEFINES = $(BYTE_ORDER) \
	-DPLUTO \
	-DKLIPS \
	-DDODGE_DH_MISSING_ZERO_BUG \
	-DDEBUG \
	-DGCC_LINT \
	-DNAT_TRAVERSAL -DVIRTUAL_IP \
	# -DLEAK_DETECTIVE

CPPFLAGS = $(HDRDIRS) $(DEFINES) \
	-DSHARED_SECRETS_FILE=\"${FINALCONFDIR}/ipsec.secrets\"

ALLFLAGS = $(CPPFLAGS) $(CFLAGS)

# libefence is a free memory allocation debugger
# Solaris 2 needs -lsocket -lnsl
LIBSPLUTO = -lgmp -lresolv # -lefence

LDFLAGS =

LIBSADNS = -lresolv # -lefence

# Solaris needs -lsocket -lnsl
LIBSWHACK =

BINNAMEPLUTO = pluto
BINNAMEWHACK = whack
BINNAMEADNS = _pluto_adns

RM = /bin/rm
RMFLAGS = -f

.SUFFIXES:
.SUFFIXES: .c .o

# files for a (source) distribution

DISTMISC = CHANGES TODO ipsec.secrets Makefile routing.txt .cvsignore \
	 pluto.8 ipsec.secrets.5

DISTGCRYPT = \
	gcryptfix.c gcryptfix.h \
	dsa.c dsa.h \
	elgamal.c elgamal.h \
	primegen.c \
	smallprime.c

DISTSRC = \
	asn1.c asn1.h \
	connections.c connections.h \
	constants.c constants.h \
	cookie.c cookie.h \
	crypto.h crypto.c \
	defs.h defs.c \
	demux.c demux.h \
	dnskey.c dnskey.h \
	endian.h \
	id.c id.h \
	ipsec_doi.c ipsec_doi.h \
	kernel.c kernel.h \
	kernel_alg.c kernel_alg.h \
	ike_alg.c ike_alg.h \
	alg_info.c alg_info.h \
	kernel_comm.c kernel_comm.h \
	log.c log.h \
	main.c \
	md2.c md2.h \
	md5.c md5.h \
	packet.c packet.h \
	pem.c pem.h \
	pkcs.c pkcs.h \
	preshared.c preshared.h \
	rnd.c rnd.h \
	server.c server.h \
	sha1.c sha1.h \
	spdb.c spdb.h \
	state.c state.h \
	timer.c timer.h \
	x509.c x509.h \
	$(DISTGCRYPT) \
	vendor.c nat_traversal.c virtual.c \
	adns.c adns.h \
	whack.c whack.h

DIST = $(DISTMISC) $(DISTSRC)


# start of support for DSS/DSA.  Not currently used.
# OBJSGCRYPT =  gcryptfix.o dsa.o elgamal.o primegen.o smallprime.o
OBJSGCRYPT =

OBJSPLUTO = asn1.o connections.o constants.o cookie.o crypto.o defs.o log.o \
	state.o main.o server.o timer.o pem.o pkcs.o x509.o id.o ipsec_doi.o kernel.o \
	kernel_comm.o demux.o packet.o preshared.o dnskey.o rnd.o spdb.o \
	vendor.o nat_traversal.o virtual.o \
	sha1.o md5.o md2.o $(OBJSGCRYPT) $(LIBDESLITE) $(FREESWANLIB)

OBJSADNS = adns.o $(FREESWANLIB)

OBJSWHACK = whack.o $(FREESWANLIB)

all: $(BINNAMEPLUTO) $(BINNAMEADNS) $(BINNAMEWHACK)

programs: all

install: all
	mkdir -p ${BINDIR}
	$(INSTALL) $(INSTBINFLAGS) $(BINNAMEPLUTO) $(BINNAMEADNS) $(BINNAMEWHACK) $(BINDIR)
	$(INSTALL) $(INSTMANFLAGS) pluto.8 $(PMANDIR)/ipsec_pluto.8
	../utils/manlink $(PMANDIR) ipsec_pluto.8
	$(INSTALL) $(INSTMANFLAGS) ipsec.secrets.5 $(FMANDIR)
	../utils/manlink $(FMANDIR) ipsec.secrets.5

alg_info_test: alg_info_test.o alg_info.o kernel_alg.o ike_alg.o constants.o defs.o log.o db_ops.o crypto.o $(LIBDESLITE) $(FREESWANLIB)
	$(CC) -o $@ $^ $(LIBSPLUTO)

# alg/libalg.o contains an already resolved object built with
# additional crypto algos inside.
OBJSPLUTO:= kernel_alg.o ike_alg.o alg_info.o db_ops.o $(OBJSPLUTO) alg/libalg.o 
# if new alg source is created in alg directory,
# trigger libalg.o rebuild
alg/libalg.o: alg
	make -C alg libalg.o
	touch alg/libalg.o

# helper for creating alg/Make.common
showdefs:
	@echo DEFINES=$(DEFINES)
	@echo CFLAGS=$(CFLAGS)
	@echo CPPFLAGS=$(CPPFLAGS)
	@echo COPTS=$(COPTS)

$(BINNAMEPLUTO): $(OBJSPLUTO) $(ALG_LIBS)
	$(CC) -o $(BINNAMEPLUTO) $(LDFLAGS) $(OBJSPLUTO) $(LIBSPLUTO)

$(BINNAMEADNS): $(OBJSADNS)
	$(CC) -o $(BINNAMEADNS) $(OBJSADNS) $(LIBSADNS)

$(BINNAMEWHACK): $(OBJSWHACK)
	$(CC) -o $(BINNAMEWHACK) $(OBJSWHACK) $(LIBSWHACK)

distlist:
	@echo $(DIST)

# Exuberant Ctags doesn't work if LC_ALL is set to something other than C

CTAGSFLAGS = -N --format=1 # fishy options required for Exuberant Ctags

tags:	$(DISTSRC)
	LC_ALL=C ctags $(CTAGSFLAGS) $(DISTSRC)

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

clean:
	$(RM) $(RMFLAGS) *.core core *~ a.out ktrace.out \
		$(OBJSPLUTO) $(BINNAMEPLUTO) \
		$(OBJSWHACK) $(BINNAMEWHACK) \
		$(OBJSADNS) $(BINNAMEADNS)
	make -C alg clean

check:
	echo no checks in lib right now.

checkprograms:

.c.o:
	$(CC) $(COPTS) $(ALLFLAGS) -c $<

# These rules are not for production use
$(FREESWANLIB):
	cd $(FREESWANLIBDIR) ; $(MAKE)

$(LIBDESLITE):
	cd $(FREESWANLIBDIR) ; $(MAKE) libdes.a

# Gather dependencies caused by explicit #includes within .c files
#
# Each .c is assumed to compile into a .o with the corresponding name.
# Only dependencies on based on "" includes are considered, not <>.
# Dependencies caused by includes within headers are not noticed.
# Unlike dependencies generated by the compiler, these include dependencies
# suppressed by conditional compilation (good, we think).
# This code can be tricked by embeding #include in comments or
# vice-versa, but we're among friends.

gatherdeps:
	@ls $(DISTSRC) | grep '\.c' | sed -e 's/\(.*\)\.c$$/\1.o: \1.c/'
	@echo
	@ls $(DISTSRC) | grep '\.c' | xargs grep '^#[ 	]*include[ 	]*"' | \
		sed -e 's/\.c:#[ 	]*include[ 	]*"/.o: /' -e 's/".*//'

# Dependencies generated by "make gatherdeps":

adns.o: adns.c
alg_info.o: alg_info.c
asn1.o: asn1.c
connections.o: connections.c
constants.o: constants.c
cookie.o: cookie.c
crypto.o: crypto.c
defs.o: defs.c
demux.o: demux.c
dnskey.o: dnskey.c
dsa.o: dsa.c
elgamal.o: elgamal.c
gcryptfix.o: gcryptfix.c
id.o: id.c
ike_alg.o: ike_alg.c
ipsec_doi.o: ipsec_doi.c
kernel.o: kernel.c
kernel_alg.o: kernel_alg.c
kernel_comm.o: kernel_comm.c
log.o: log.c
main.o: main.c
md2.o: md2.c
md5.o: md5.c
nat_traversal.o: nat_traversal.c
packet.o: packet.c
pem.o: pem.c
pkcs.o: pkcs.c
preshared.o: preshared.c
primegen.o: primegen.c
rnd.o: rnd.c
server.o: server.c
sha1.o: sha1.c
smallprime.o: smallprime.c
spdb.o: spdb.c
state.o: state.c
timer.o: timer.c
vendor.o: vendor.c
virtual.o: virtual.c
whack.o: whack.c
x509.o: x509.c

adns.o: adns.h
alg_info.o: alg_info.h
alg_info.o: constants.h
alg_info.o: defs.h
alg_info.o: log.h
alg_info.o: sha1.h
alg_info.o: md5.h
alg_info.o: crypto.h
alg_info.o: kernel_alg.h
alg_info.o: ike_alg.h
asn1.o: constants.h
asn1.o: defs.h
asn1.o: asn1.h
asn1.o: log.h
asn1.o: pem.h
connections.o: constants.h
connections.o: defs.h
connections.o: id.h
connections.o: x509.h
connections.o: connections.h
connections.o: packet.h
connections.o: demux.h
connections.o: state.h
connections.o: timer.h
connections.o: ipsec_doi.h
connections.o: server.h
connections.o: kernel.h
connections.o: log.h
connections.o: preshared.h
connections.o: adns.h
connections.o: dnskey.h
connections.o: whack.h
connections.o: alg_info.h
connections.o: ike_alg.h
connections.o: kernel_alg.h
connections.o: nat_traversal.h
connections.o: virtual.h
constants.o: constants.h
constants.o: defs.h
constants.o: log.h
constants.o: packet.h
cookie.o: constants.h
cookie.o: defs.h
cookie.o: sha1.h
cookie.o: rnd.h
cookie.o: cookie.h
crypto.o: constants.h
crypto.o: defs.h
crypto.o: state.h
crypto.o: log.h
crypto.o: md5.h
crypto.o: sha1.h
crypto.o: crypto.h
crypto.o: alg_info.h
crypto.o: ike_alg.h
defs.o: constants.h
defs.o: defs.h
defs.o: log.h
defs.o: whack.h
demux.o: constants.h
demux.o: defs.h
demux.o: cookie.h
demux.o: id.h
demux.o: x509.h
demux.o: connections.h
demux.o: state.h
demux.o: packet.h
demux.o: md5.h
demux.o: sha1.h
demux.o: crypto.h
demux.o: ike_alg.h
demux.o: log.h
demux.o: demux.h
demux.o: ipsec_doi.h
demux.o: timer.h
demux.o: whack.h
demux.o: server.h
demux.o: nat_traversal.h
demux.o: vendor.h
dnskey.o: adns.h
dnskey.o: constants.h
dnskey.o: defs.h
dnskey.o: id.h
dnskey.o: log.h
dnskey.o: x509.h
dnskey.o: connections.h
dnskey.o: preshared.h
dnskey.o: dnskey.h
dnskey.o: packet.h
dnskey.o: timer.h
dsa.o: constants.h
dsa.o: defs.h
dsa.o: log.h
dsa.o: rnd.h
dsa.o: gcryptfix.h
dsa.o: dsa.h
elgamal.o: constants.h
elgamal.o: defs.h
elgamal.o: log.h
elgamal.o: rnd.h
elgamal.o: gcryptfix.h
elgamal.o: elgamal.h
gcryptfix.o: constants.h
gcryptfix.o: defs.h
gcryptfix.o: log.h
gcryptfix.o: rnd.h
gcryptfix.o: gcryptfix.h
id.o: constants.h
id.o: defs.h
id.o: id.h
id.o: log.h
id.o: x509.h
id.o: connections.h
id.o: packet.h
ike_alg.o: constants.h
ike_alg.o: defs.h
ike_alg.o: sha1.h
ike_alg.o: md5.h
ike_alg.o: crypto.h
ike_alg.o: state.h
ike_alg.o: packet.h
ike_alg.o: kernel.h
ike_alg.o: log.h
ike_alg.o: whack.h
ike_alg.o: spdb.h
ike_alg.o: alg_info.h
ike_alg.o: ike_alg.h
ike_alg.o: db_ops.h
ike_alg.o: id.h
ike_alg.o: x509.h
ike_alg.o: connections.h
ipsec_doi.o: constants.h
ipsec_doi.o: defs.h
ipsec_doi.o: state.h
ipsec_doi.o: id.h
ipsec_doi.o: x509.h
ipsec_doi.o: connections.h
ipsec_doi.o: preshared.h
ipsec_doi.o: packet.h
ipsec_doi.o: demux.h
ipsec_doi.o: adns.h
ipsec_doi.o: dnskey.h
ipsec_doi.o: kernel.h
ipsec_doi.o: log.h
ipsec_doi.o: cookie.h
ipsec_doi.o: server.h
ipsec_doi.o: spdb.h
ipsec_doi.o: timer.h
ipsec_doi.o: rnd.h
ipsec_doi.o: ipsec_doi.h
ipsec_doi.o: whack.h
ipsec_doi.o: pkcs.h
ipsec_doi.o: sha1.h
ipsec_doi.o: md5.h
ipsec_doi.o: crypto.h
ipsec_doi.o: ike_alg.h
ipsec_doi.o: kernel_alg.h
ipsec_doi.o: alg_info.h
ipsec_doi.o: vendor.h
ipsec_doi.o: nat_traversal.h
ipsec_doi.o: virtual.h
kernel.o: constants.h
kernel.o: defs.h
kernel.o: rnd.h
kernel.o: id.h
kernel.o: x509.h
kernel.o: connections.h
kernel.o: state.h
kernel.o: timer.h
kernel.o: kernel.h
kernel.o: log.h
kernel.o: server.h
kernel.o: whack.h
kernel.o: alg_info.h
kernel.o: kernel_alg.h
kernel.o: packet.h
kernel.o: nat_traversal.h
kernel_alg.o: constants.h
kernel_alg.o: defs.h
kernel_alg.o: id.h
kernel_alg.o: x509.h
kernel_alg.o: connections.h
kernel_alg.o: state.h
kernel_alg.o: packet.h
kernel_alg.o: spdb.h
kernel_alg.o: kernel.h
kernel_alg.o: kernel_alg.h
kernel_alg.o: alg_info.h
kernel_alg.o: log.h
kernel_alg.o: whack.h
kernel_alg.o: db_ops.h
kernel_comm.o: constants.h
kernel_comm.o: defs.h
kernel_comm.o: id.h
kernel_comm.o: x509.h
kernel_comm.o: connections.h
kernel_comm.o: whack.h
kernel_comm.o: packet.h
kernel_comm.o: demux.h
kernel_comm.o: state.h
kernel_comm.o: ipsec_doi.h
kernel_comm.o: kernel.h
kernel_comm.o: kernel_comm.h
kernel_comm.o: log.h
kernel_comm.o: preshared.h
kernel_comm.o: adns.h
kernel_comm.o: dnskey.h
kernel_comm.o: server.h
kernel_comm.o: kernel_alg.h
kernel_comm.o: ike_alg.h
kernel_comm.o: db_ops.h
log.o: constants.h
log.o: defs.h
log.o: log.h
log.o: state.h
log.o: id.h
log.o: x509.h
log.o: connections.h
log.o: whack.h
main.o: constants.h
main.o: defs.h
main.o: id.h
main.o: x509.h
main.o: connections.h
main.o: packet.h
main.o: demux.h
main.o: server.h
main.o: kernel.h
main.o: log.h
main.o: preshared.h
main.o: adns.h
main.o: dnskey.h
main.o: rnd.h
main.o: state.h
main.o: sha1.h
main.o: md5.h
main.o: crypto.h
main.o: virtual.h
main.o: nat_traversal.h
md2.o: md2.h
md5.o: md5.h
md5.o: endian.h
nat_traversal.o: constants.h
nat_traversal.o: defs.h
nat_traversal.o: log.h
nat_traversal.o: id.h
nat_traversal.o: x509.h
nat_traversal.o: connections.h
nat_traversal.o: packet.h
nat_traversal.o: demux.h
nat_traversal.o: whack.h
nat_traversal.o: state.h
nat_traversal.o: server.h
nat_traversal.o: timer.h
nat_traversal.o: sha1.h
nat_traversal.o: md5.h
nat_traversal.o: crypto.h
nat_traversal.o: vendor.h
nat_traversal.o: cookie.h
nat_traversal.o: kernel.h
nat_traversal.o: nat_traversal.h
nat_traversal.o: ike_alg.h
packet.o: constants.h
packet.o: defs.h
packet.o: log.h
packet.o: packet.h
packet.o: whack.h
pem.o: constants.h
pem.o: defs.h
pem.o: log.h
pem.o: md5.h
pem.o: pem.h
pkcs.o: constants.h
pkcs.o: defs.h
pkcs.o: asn1.h
pkcs.o: log.h
pkcs.o: id.h
pkcs.o: x509.h
pkcs.o: pkcs.h
preshared.o: constants.h
preshared.o: defs.h
preshared.o: id.h
preshared.o: x509.h
preshared.o: connections.h
preshared.o: state.h
preshared.o: preshared.h
preshared.o: adns.h
preshared.o: dnskey.h
preshared.o: log.h
preshared.o: whack.h
preshared.o: pkcs.h
preshared.o: nat_traversal.h
primegen.o: constants.h
primegen.o: defs.h
primegen.o: log.h
primegen.o: rnd.h
primegen.o: gcryptfix.h
rnd.o: sha1.h
rnd.o: constants.h
rnd.o: defs.h
rnd.o: rnd.h
rnd.o: log.h
rnd.o: timer.h
server.o: constants.h
server.o: defs.h
server.o: state.h
server.o: id.h
server.o: x509.h
server.o: connections.h
server.o: kernel.h
server.o: log.h
server.o: server.h
server.o: timer.h
server.o: packet.h
server.o: demux.h
server.o: kernel_comm.h
server.o: preshared.h
server.o: adns.h
server.o: dnskey.h
server.o: whack.h
server.o: nat_traversal.h
sha1.o: sha1.h
sha1.o: endian.h
smallprime.o: constants.h
smallprime.o: defs.h
smallprime.o: gcryptfix.h
spdb.o: constants.h
spdb.o: defs.h
spdb.o: id.h
spdb.o: x509.h
spdb.o: connections.h
spdb.o: state.h
spdb.o: packet.h
spdb.o: preshared.h
spdb.o: kernel.h
spdb.o: log.h
spdb.o: spdb.h
spdb.o: whack.h
spdb.o: sha1.h
spdb.o: md5.h
spdb.o: crypto.h
spdb.o: alg_info.h
spdb.o: kernel_alg.h
spdb.o: ike_alg.h
spdb.o: db_ops.h
spdb.o: nat_traversal.h
state.o: constants.h
state.o: defs.h
state.o: id.h
state.o: x509.h
state.o: connections.h
state.o: state.h
state.o: kernel.h
state.o: log.h
state.o: packet.h
state.o: preshared.h
state.o: rnd.h
state.o: timer.h
state.o: whack.h
state.o: demux.h
state.o: ipsec_doi.h
state.o: sha1.h
state.o: md5.h
state.o: crypto.h
timer.o: constants.h
timer.o: defs.h
timer.o: id.h
timer.o: x509.h
timer.o: connections.h
timer.o: state.h
timer.o: packet.h
timer.o: demux.h
timer.o: ipsec_doi.h
timer.o: kernel.h
timer.o: server.h
timer.o: log.h
timer.o: rnd.h
timer.o: timer.h
timer.o: whack.h
timer.o: nat_traversal.h
vendor.o: constants.h
vendor.o: defs.h
vendor.o: log.h
vendor.o: md5.h
vendor.o: id.h
vendor.o: x509.h
vendor.o: connections.h
vendor.o: packet.h
vendor.o: demux.h
vendor.o: whack.h
vendor.o: vendor.h
vendor.o: nat_traversal.h
virtual.o: constants.h
virtual.o: defs.h
virtual.o: log.h
virtual.o: id.h
virtual.o: x509.h
virtual.o: connections.h
virtual.o: whack.h
virtual.o: virtual.h
whack.o: constants.h
whack.o: defs.h
whack.o: whack.h
x509.o: constants.h
x509.o: defs.h
x509.o: log.h
x509.o: id.h
x509.o: asn1.h
x509.o: x509.h
x509.o: preshared.h
x509.o: md2.h
x509.o: md5.h
x509.o: sha1.h
x509.o: whack.h
