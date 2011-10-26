# Makefile for the mgetty fax package
#
# SCCS-ID: $Id: Makefile,v 4.63 2005/02/27 11:58:12 gert Exp $ (c) Gert Doering
#
# this is the C compiler to use (on SunOS, the standard "cc" does not
# grok my code, so please use gcc there. On ISC 4.0, use "icc".).
#CC=gcc
#CC=cc
#
#### C Compiler Flags ####
#
# For SCO Unix 3.2v4, it may be necessary to define -D__STDC__=0
# If you have problems with dial-in / dial-out on the same line (e.g.
# 'cu' telling you "CAN'T ACCESS DEVICE"), you should try -DBROKEN_SCO_324
# If the compiler barfs about my getopt() prototype, change it (mgetty.h)
# If the linker cannot find "syslog()" (compiled with SYSLOG defined),
# link "-lsocket".
#
# On SCO Unix 3.2.2, select(S) refuses to sleep less than a second,
# so use poll(S) instead. Define -DUSE_POLL
#
# For Systems with a "login uid" (man setluid()), define -DSECUREWARE
# (All SCO Systems have this). Maybe you've to link some special library
# for it, on SCO it's "-lprot_s".
#
#
# Add "-DSVR4" to compile on System V Release 4 unix
# For SVR4.2, add "-DSVR4 -DSVR42" to the CFLAGS line.
#
# For Linux, you don't have to define anything
#
# For SunOS 4.x, please define -Dsunos4.
#   (We can't use "#ifdef sun" because that's defined on solaris as well)
#   If you use gcc, add -Wno-missing-prototypes, our code is OK, but
#   the Sun4 header files lack a lot standard definitions...
#   Be warned, Hardware handshake (and serial operations in general)
#   work a lot more reliably with patch 100513-05 (jumbo tty patch)!
#
# For Solaris 2.x, please define -Dsolaris2, which will automatically
#   #define SVR4.
#
# Add "-DISC" to compile on Interactive Unix. For posixized ISC 4.0 you
# may have to add -D_POSIX_SOURCE
#
# For IBM AIX 4.x, no changes should be necessary. For AIX 3.x, it might
# be necessary to add -D_ALL_SOURCE and -DUSE_POLL to the CFLAGS line.
# [If you experience "strange" problems with AIX, report to me...!]
#
# Add "-D_3B1_ -DUSE_READ -D_NOSTDLIB_H -DSHORT_FILENAMES" to compile
# on the AT&T 3b1 machine -g.t.
#
# Add "-DMEIBE" to compile on the Panasonic (Matsushita Electric
#	industry) BE workstation
#
# When compiling on HP/UX, make sure that the compiler defines _HPUX_SOURCE, 
#     if it doesn't, add "-D_HPUX_SOURCE" to the CFLAGS line.
#
# On NeXTStep, add "-DNEXTSGTTY -DBSD". To compile vgetty or if you are
#     brave, you have to use "-posix -DBSD".
#
# On the MIPS RiscOS, add "-DMIPS -DSVR4 -systype svr4" (the other
#     subsystems are too broken. Watch out that *all* programs honour
#     the SVR4 locking convention, "standard" UUCP and CU do not!)
#
# For (otherwise not mentioned) systems with BSD utmp handling, define -DBSD
#
# Add "-D_NOSTDLIB_H" if you don't have <stdlib.h>
#
# Add "-DPOSIX_TERMIOS" to use POSIX termios.h, "-DSYSV_TERMIO" to use
#     the System 5 termio.h style. (Default set in tio.h)
#
# For machines without the select() call:
#     Add "-DUSE_POLL" if you don't have select, but do have poll
#     Add "-DUSE_READ" if you don't have select or poll (ugly)
#
# For older SVR systems (with a filename length restriction to 14
#     characters), define -DSHORT_FILENAMES
#
# For Systems that default to non-interruptible system calls (symptom:
# timeouts in do_chat() don't work reliably) but do have siginterrupt(),
# define -DHAVE_SIGINTERRUPT. This is the default if BSD is defined.
#
# For Systems with broken termios / VMIN/VTIME mechanism (symptom: mgetty
# hangs in "waiting for line to clear"), define -DBROKEN_VTIME. Notably
# this hits FreeBSD 0.9 and some SVR4.2 users...
#
# If you don't have *both* GNU CC and GNU AS, remove "-pipe"
#
# Disk statistics:
#
# The following macros select one of 5 different variants of partition
# information grabbing.  AIX, Linux, 3b1 and SVR4 systems will figure
# this out themselves.  You can test whether you got this right by
# running "make testdisk".  If it fails, consult getdisk.c for
# further instructions.
#
#	    BSDSTATFS     - BSD/hp-ux/SunOS/Dynix/vrios
#			    2-parameter statfs()
#	    ULTRIXSTATFS  - Ultrix wacko statfs
#	    SVR4	  - SVR4 statvfs()
#	    SVR3	  - SVR3/88k/Apollo/SCO 4-parameter statfs()
#	    USTAT	  - ustat(), no statfs etc.
#
#CFLAGS=-Wall -O2 -pipe -DSECUREWARE -DUSE_POLL
#CFLAGS=-O2 -Wall -pipe
#CFLAGS+=-O2 -Wall -pipe
#CFLAGS=-O -DSVR4
#CFLAGS=-O -DSVR4 -DSVR42
#CFLAGS=-O -DUSE_POLL
#CFLAGS=-Wall -g -O2 -pipe
# 3B1: You can remove _NOSTDLIB_H and USE_READ if you have the
# networking library and gcc.
#CFLAGS=-D_3B1_ -D_NOSTDLIB_H -DUSE_READ -DSHORT_FILENAMES
#CFLAGS=-std -DPOSIX_TERMIOS -O2 -D_BSD -DBSD	# for OSF/1 (w/ /bin/cc)
#CFLAGS=-DNEXTSGTTY -DBSD -O2			# for NeXT with sgtty (better!)
#CFLAGS=-posix -DUSE_VARARGS -DBSD -O2		# for NeXT with POSIX
#CFLAGS=-D_HPUX_SOURCE -Aa -DBSDSTATFS		# for HP-UX 9.x
#CFLAGS=-cckr -D__STDC__ -O -DUSE_READ 		# for IRIX 5.2 and up


#
# LDFLAGS specify flags to pass to the linker. You could specify
# 	special link modes, binary formats, whatever...
#
# For the 3B1, add "-s -shlib". For other systems, nothing is needed.
#
# LIBS specify extra libraries to link to the programs
#       (do not specify the libraries in the LDFLAGS statement)
#
# To use the "setluid()" function on SCO, link "-lprot", and to use
# the "syslog()" function, link "-lsocket".
#
# For SVR4(.2) and Solaris 2, you may need "-lsocket -lnsl" for syslog().
#
# For ISC, add "-linet -lpt" (and -lcposix, if necessary)
#
# For Sequent Dynix/ptx, you have to add "-lsocket"
#
# For OSF/1, add "-lbsd".
#
# On SCO Xenix, add -ldir -lx
#
# For FreeBSD and NetBSD, add "-lutil" if the linker complains about
# 	"utmp.o: unresolved symbol _login"
# For Linux, add "-lutil" if the linker complains about "updwtmp".
#
#LDFLAGS=
#LIBS=
#LIBS=-lprot -lsocket				# SCO Unix
#LIBS=-lsocket
#LIBS=-lbsd					# OSF/1
#LIBS=-lutil					# FreeBSD or Linux/GNU libc2
#LDFLAGS=-posix					# NeXT with POSIX
#LDFLAGS=-s -shlib				# 3B1
#
#
# the following things are mainly used for ``make install''
#
#
# program to use for installing files
#
# "-o <username>" sets the username that will own the binaries after installing.
# "-g <group>" sets the group
# "-c" means "copy" (as opposed to "move")
#
# if your systems doesn't have one, use the shell script that I provide
# in "inst.sh" (taken from X11R5). Needed on IRIX5.2
INSTALL=install -c -o bin -g bin
#INSTALL=install -c -o root -g wheel		# NeXT/BSD
#INSTALL=/usr/ucb/install -c -o bin -g bin	# AIX, Solaris 2.x
#INSTALL=installbsd -c -o bin -g bin		# OSF/1, AIX 4.1, 4.2
#INSTALL=/usr/bin/X11/bsdinst -c -o bin 	# IRIX
#
# prefix, where most (all?) of the stuff lives, usually /usr/local or /usr
#
#prefix=/usr/local
prefix=/
#
# prefix for all the spool directories (usually /usr/spool or /var/spool)
#
spool=/var/spool
#
# where the mgetty + sendfax binaries live (used for "make install")
#
SBINDIR=$(prefix)/sbin
#
# where the user executable binaries live
#
BINDIR=$(prefix)/bin
#
# where the font+coverpage files go
#
LIBDIR=$(prefix)/lib/mgetty+sendfax
#
# where the configuration files (*.config, aliases, fax.allow/deny) go to
#
#CONFDIR=$(prefix)/etc/mgetty+sendfax
#CONFDIR=/etc/default/
CONFDIR=$(prefix)/etc/config
#
#
# where mgetty PID files (mgetty.pid) go to
# (the faxrunqd PID file lives in FAX_SPOOL_OUT/ due to permission reasons)
#
VARRUNDIR=/var/run
#
# the fax spool directory
#
FAX_SPOOL=$(spool)/fax
FAX_SPOOL_IN=$(FAX_SPOOL)/incoming
FAX_SPOOL_OUT=$(FAX_SPOOL)/outgoing
#
# the user that owns the "outgoing fax queue" (FAX_SPOOL_OUT)
# this user must exist in the system, otherwise faxspool will not work!
#
# faxrunq and faxrunqd should run under this user ID, and nothing else.  
# This user needs access to the modems of course.  
#
# (it's possible to run faxrunq(d) as root, but the FAX_OUT_USER 
#  MUST NOT BE root or any other privileged account).
#
FAX_OUT_USER=fax
#
#
# Where section 1 manual pages should be placed
MAN1DIR=$(prefix)/man/man1
#
# Where section 4 manual pages (mgettydefs.4) should be placed
MAN4DIR=$(prefix)/man/man4
#
# Section 5 man pages (faxqueue.5)
MAN5DIR=$(prefix)/man/man5
#
# Section 8 man pages (sendfax.8)
MAN8DIR=$(prefix)/man/man8
#
# Where the GNU Info-Files are located
#
INFODIR=$(prefix)/info
#
#
# A shell that understands bourne-shell syntax
#  Usually this will be /bin/sh or /usr/bin/sh, but bash or ksh are fine.
#  (on some ultrix systems, you may need /bin/sh5 here)
#
SHELL=/bin/sh
#
# If your shell requires pre-posix syntax to disable traps ('trap 0' 
#  instead of 'trap - 0'), set this to "0" (very rarely needed)
#
SHELL_TRAP_POSIX=1
#
# If you have problems with the awk-programs in the fax/ shell scripts,
# try using "nawk" or "gawk" (or whatever works...) here
# needed on most SunOS/Solaris/ISC/NeXTStep versions.
#
AWK=awk
#
# A few (very few) programs want Perl, preferably Perl5. This define
# tells them where to find it. You can use everything except "faxrunqd"
# and the "tkperl" frontends without PERL, so don't worry if you don't
# have it.
# If you specify command line arguments (-w), don't forget the quotes!
PERL="/usr/bin/perl -w"
#
# If you have Perl with TK extentions, define it here. This may be the
# same as PERL=... above, or different, if you have TkPerl statically
# linked.
TKPERL=/usr/bin/tkperl
#
#
# An echo program that understands escapes like "\n" for newline or
# "\c" for "no-newline-at-end". On SunOS, this is /usr/5bin/echo, in the
# bash, it's "echo -e"
# (don't forget the quotes, otherwise compiling mksed will break!!)
#
# If you do not have *any* echo program at all that will understand "\c",
# please use the "mg.echo" program provided in the compat/ subdirectory.
# Set ECHO="mg.echo" and INSTALL_MECHO to mg.echo
#
ECHO="echo"
#
# INSTALL_MECHO=mg.echo

#
# for mgetty, that's it. If you want to use the voice
# extentions, go ahead (don't forget to read the manual!)

# To maintain security, I recommend creating a new group for
# users who are allowed to manipulate the recorded voice messages.
PHONE_GROUP=phone
PHONE_PERMS=770

# Add -DNO_STRSTR to CFLAGS if you don't have strstr().

# create hard/soft links (-s will be added by vgetty Makefile)
LN=ln
#LN=/usr/5bin/ln

RM=rm
MV=mv

#
# Nothing to change below this line ---------------------------------!
#
MR=1.1
SR=33
DIFFR=1.1.32
#
#
OBJS=mgetty.o logfile.o do_chat.o locks.o utmp.o logname.o login.o \
     mg_m_init.o modem.o faxrec.o ring.o \
     faxlib.o faxsend.o faxrecp.o class1.o class1lib.o faxhng.o \
     io.o gettydefs.o tio.o cnd.o getdisk.o goodies.o \
     config.o conf_mg.o do_stat.o

SFAXOBJ=sendfax.o logfile.o locks.o modem.o \
     faxlib.o faxsend.o faxrecp.o class1.o class1lib.o faxhng.o \
     io.o tio.o getdisk.o config.o conf_sf.o goodies.o

#all:	bin-all doc-all
all: bin-all

bin-all: mgetty sendfax newslock sedscript subdirs call-back 

# a few C files need extra compiler arguments

mgetty.o : mgetty.c syslibs.h mgetty.h ugly.h policy.h tio.h fax_lib.h \
	config.h mg_utmp.h Makefile
	$(CC) $(CFLAGS) -DVARRUNDIR=\"$(VARRUNDIR)\" -c mgetty.c

conf_mg.o : conf_mg.c mgetty.h ugly.h policy.h syslibs.h \
	config.h conf_mg.h Makefile
	$(CC) $(CFLAGS) -DFAX_SPOOL_IN=\"$(FAX_SPOOL_IN)\" \
		-DCONFDIR=\"$(CONFDIR)\" -c conf_mg.c

conf_sf.o : conf_sf.c mgetty.h ugly.h policy.h syslibs.h \
	config.h conf_sf.h Makefile
	$(CC) $(CFLAGS) -DCONFDIR=\"$(CONFDIR)\" -c conf_sf.c

login.o : login.c mgetty.h ugly.h config.h policy.h mg_utmp.h  Makefile
	$(CC) $(CFLAGS) -DCONFDIR=\"$(CONFDIR)\" -c login.c

cnd.o : cnd.c syslibs.h policy.h mgetty.h ugly.h config.h  Makefile
	$(CC) $(CFLAGS) -DCONFDIR=\"$(CONFDIR)\" -c cnd.c

logname.o : logname.c syslibs.h mgetty.h policy.h tio.h mg_utmp.h Makefile

# here are the binaries...

mgetty: $(OBJS)
	$(CC) -o mgetty $(OBJS) $(LDFLAGS) $(LIBS)

sendfax: $(SFAXOBJ)
	$(CC) -o sendfax $(SFAXOBJ) $(LDFLAGS) $(LIBS)

# sentinelized binaries for runtime testing...
sentinel:	mgetty.sen sendfax.sen

mgetty.sen: $(OBJS)
	sentinel -v $(CC) -o mgetty.sen $(OBJS) $(LDFLAGS) $(LIBS)

sendfax.sen: $(SFAXOBJ)
	sentinel -v $(CC) -o sendfax.sen $(SFAXOBJ) $(LDFLAGS) $(LIBS)

# subdirectories...

subdirs:
	cd g3 ;    $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "LIBS=$(LIBS)" all
	cd tools ; $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "LIBS=$(LIBS)" all
	cd fax ;   $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "LIBS=$(LIBS)" "FAX_SPOOL_OUT=$(FAX_SPOOL_OUT)" "FAX_OUT_USER=$(FAX_OUT_USER)" "CONFDIR=$(CONFDIR)" all

call-back:
	@$(MAKE) mgetty
	cd callback ; $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "CONFDIR=$(CONFDIR)" "VARRUNDIR=$(VARRUNDIR)" "LIBS=$(LIBS)" all

contrib-all: 
	cd contrib ; $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "LIBS=$(LIBS)" all

doc-all: 
	cd doc ; $(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS) -I.." "LDFLAGS=$(LDFLAGS)" "LIBS=$(LIBS)" doc-all

# things...

getdisk: getdisk.c
	$(CC) $(CFLAGS) -DTESTDISK getdisk.c -o getdisk

testdisk:	getdisk
	./getdisk / .


# README PROBLEMS
DISTRIB=README.1st THANKS TODO BUGS FTP Recommend \
	inittab.aix inst.sh version.h \
	Makefile ChangeLog policy.h-dist ftp.sh mkidirs \
	login.cfg.in mgetty.cfg.in sendfax.cfg.in \
	dialin.config faxrunq.config \
        mgetty.c mgetty.h ugly.h do_chat.c logfile.c logname.c locks.c \
	mg_m_init.c modem.c ring.c class1.h class1.c class1lib.c \
	faxrec.c faxrecp.c faxsend.c faxlib.c fax_lib.h sendfax.c \
	io.c tio.c tio.h gettydefs.c login.c do_stat.c faxhng.c \
	config.h config.c conf_sf.h conf_sf.c conf_mg.h conf_mg.c \
	cnd.c getdisk.c mksed.c utmp.c mg_utmp.h syslibs.h goodies.c \
	g3/Makefile g3/g3cat.c g3/g32pbm.c g3/g3.c g3/g3.h \
	g3/pbm2g3.c g3/run_tbl.c g3/sff2g3.c g3/test-ref.g3

noident: policy.h
	    for file in `find . -type f -name "*.[ch]" -print` ; do \
	    echo "$$file..."; \
	    case $$file in \
	      *.c) \
		mv -f $$file tmp-noident; \
		sed -e "s/^#ident\(.*\)$$/static char sccsid[] =\1;/" <tmp-noident >$$file; \
		;; \
	      *.h) \
		mv -f $$file tmp-noident; \
		f=`basename $$file .h`; \
		sed -e "s/^#ident\(.*\)$$/static char sccs_$$f[] =\1;/" <tmp-noident >$$file; \
		;; \
	    esac; \
	done
	$(MAKE) "CC=$(CC)" "CFLAGS=$(CFLAGS)" all

sedscript: mksed
	./mksed >sedscript
	chmod 700 sedscript

mksed: mksed.c policy.h Makefile 
#	$(CC) $(CFLAGS) -DBINDIR=\"$(BINDIR)\" -DSBINDIR=\"$(SBINDIR)\" 
	gcc -DBINDIR=\"$(BINDIR)\" -DSBINDIR=\"$(SBINDIR)\" \
		-DLIBDIR=\"$(LIBDIR)\" \
		-DCONFDIR=\"$(CONFDIR)\" \
		-DFAX_SPOOL=\"$(FAX_SPOOL)\" \
		-DFAX_SPOOL_IN=\"$(FAX_SPOOL_IN)\" \
		-DFAX_SPOOL_OUT=\"$(FAX_SPOOL_OUT)\" \
		-DFAX_OUT_USER=\"$(FAX_OUT_USER)\" \
		-DVARRUNDIR=\"$(VARRUNDIR)\" \
		-DAWK=\"$(AWK)\" \
		-DPERL=\"$(PERL)\" -DTKPERL=\"$(TKPERL)\" \
		-DECHO=\"$(ECHO)\" \
		-DSHELL=\"$(SHELL)\" \
		-DSHELL_TRAP_POSIX=$(SHELL_TRAP_POSIX) \
	-o mksed mksed.c

policy.h-dist: policy.h
	@rm -f policy.h-dist
	cp policy.h policy.h-dist
	@chmod u+w policy.h-dist

version.h: $(DISTRIB)
	rm -f version.h
	if expr "$(MR)" : "[0-9].[13579]" >/dev/null ; then \
	    date=`date "+%b%d"` ;\
	    echo "char * mgetty_version = \"interim release $(MR).$(SR)-$$date\";" >version.h ;\
	else \
	    echo "char * mgetty_version = \"stable release $(MR).$(SR)\";" >version.h ;\
	fi
	chmod 444 version.h

mgetty$(MR).$(SR).tar.gz:	$(DISTRIB)
	rm -f mgetty-$(MR).$(SR)
	ln -sf . mgetty-$(MR).$(SR)
	cd voice ; $(MAKE) fullclean && cvs update -d .
	( echo "$(DISTRIB)" | tr " " "\\012" ; \
	  for i in `find . -name .files -print | sed -e 's;^./;;` ; do \
	      cat $$i | sed -e '/^\.files/d' -e 's;^;'`dirname $$i`'/;' ; \
	  done ; \
	  find voice -type f -print | grep -v CVS ; \
	) \
	    | sed -e 's;^;mgetty-$(MR).$(SR)/;g' \
	    | gtar cvvfT mgetty$(MR).$(SR).tar -
	gzip -f -9 -v mgetty$(MR).$(SR).tar

tar:	mgetty$(MR).$(SR).tar.gz

diff:	mgetty$(DIFFR)-$(MR).$(SR).diff.gz

sign:	tar
	pgp -sab mgetty$(MR).$(SR).tar.gz

mgetty$(DIFFR)-$(MR).$(SR).diff.gz: \
	mgetty$(DIFFR).tar.gz mgetty$(MR).$(SR).tar.gz
	-rm -rf /tmp/mgd
	mkdir /tmp/mgd
	gtar xvCfz /tmp/mgd mgetty$(DIFFR).tar.gz
	gtar xvCfz /tmp/mgd mgetty$(MR).$(SR).tar.gz
	( cd /tmp/mgd ; \
	  gdiff -u3 --ignore-space-change --recursive --new-file -I "^#ident" \
		mgetty-$(DIFFR) mgetty-$(MR).$(SR) ; \
		exit 0 ) >mgetty$(DIFFR)-$(MR).$(SR).diff
	rm -rf /tmp/mgd
	gzip -f -9 -v mgetty$(DIFFR)-$(MR).$(SR).diff

mg.uue:	mgetty$(MR).$(SR).tar.gz
	uuencode mgetty$(MR).$(SR)-`date +%b%d`.tar.gz <mgetty$(MR).$(SR).tar.gz >mg.uue

uu:	mg.uue

uu2:	mg.uue
	split -3600 mg.uue mg.uu.

# this is for automatic uploading to the beta site. 
# DO NOT USE IT if you're not ME! Please!
#
beta:	tar diff sign
	test `hostname` = greenie.muc.de || exit 1
# local
	cp mgetty$(MR).$(SR).tar.gz /pub/mgetty-archive/
	cp mgetty$(DIFFR)-$(MR).$(SR).diff.gz /pub/mgetty-archive/

	-cvs commit -m 'new version released' version.h
# master ftp/www site
	./ftp.sh $(MR).$(SR) alpha.greenie.net \
		'~ftp/pub/mgetty/source/$(MR)'
	ssh alpha.greenie.net './beta $(MR) $(SR) $(DIFFR)'

# old master ftp site
	ssh home.leo.org -l doering 'cd $$HOME ; ./beta'

# send to Marc and Knarf
	head -30 ChangeLog |mail -s "mgetty$(MR).$(SR).tar.gz on greenie/alpha" mgetty@knarf.de marc marcs
#	-./ftp.sh $(MR).$(SR) ftp.camelot.de /pub/incoming
#	-./ftp.sh $(MR).$(SR) poseidon.thphy.uni-duesseldorf.de /incoming

#shar1:	$(DISTRIB)
#	shar -M -c -l 40 -n mgetty+sendfax-$(MR).$(SR) -a -o mgetty.sh $(DISTRIB)
#
#shar:	$(DISTRIB)
#	shar -M $(DISTRIB) >mgetty$(MR).$(SR).sh

doc-tar:
	cd doc ; $(MAKE) "VS=$(MR).$(SR)" doc-tar

policy.h:
	@echo
	@echo "You have to create your local policy.h first."
	@echo "Copy policy.h-dist and edit it."
	@echo
	@exit 1

clean:
	rm -f *.o getdisk compat/*.o newslock
	cd g3 ; $(MAKE) clean
	cd fax ; $(MAKE) clean
	cd tools ; $(MAKE) clean
	cd callback ; $(MAKE) clean
	cd contrib ; $(MAKE) clean
	cd doc ; $(MAKE) clean
	cd voice ; $(MAKE) clean

fullclean:
	rm -f *.o compat/*.o mgetty sendfax testgetty getdisk \
			mksed sedscript newslock *~ \
			sendfax.config mgetty.config login.config
	cd g3 ; $(MAKE) fullclean
	cd fax ; $(MAKE) fullclean
	cd tools ; $(MAKE) fullclean
	cd callback ; $(MAKE) fullclean
	cd contrib ; $(MAKE) fullclean
	cd doc ; $(MAKE) fullclean
	cd voice ; $(MAKE) fullclean

login.config: login.cfg.in sedscript
	./sedscript <login.cfg.in >login.config

mgetty.config: mgetty.cfg.in sedscript
	./sedscript <mgetty.cfg.in >mgetty.config

sendfax.config: sendfax.cfg.in sedscript
	./sedscript <sendfax.cfg.in >sendfax.config

newslock: compat/newslock.c
	$(CC) $(CFLAGS) -o newslock compat/newslock.c

# internal: use this to create a "clean" mgetty+sendfax tree
bindist: all doc-all sedscript
	-rm -rf bindist
	./mkidirs bindist$(prefix) bindist$(spool)
	bd=`pwd`/bindist; PATH=`pwd`:"$$PATH" $(MAKE) prefix=$$bd$(prefix) \
		BINDIR=$$bd$(BINDIR) SBINDIR=$$bd$(SBINDIR) \
		LIBDIR=$$bd$(LIBDIR) CONFDIR=$$bd$(CONFDIR) \
		spool=$$bd$(spool) FAX_SPOOL=$$bd$(FAX_SPOOL) \
		FAX_SPOOL_IN=$$bd$(FAX_SPOOL_IN) \
		FAX_SPOOL_OUT=$$bd$(FAX_SPOOL_OUT) \
		MAN1DIR=$$bd$(MAN1DIR) MAN4DIR=$$bd$(MAN4DIR) \
		MAN5DIR=$$bd$(MAN5DIR) MAN8DIR=$$bd$(MAN8DIR) \
		INFODIR=$$bd$(INFODIR) install
	cd bindist; gtar cvvfz mgetty$(MR).$(SR)-bin.tgz *

romfs:
	$(ROMFSINST) /bin/mgetty

install: install.bin install.doc

install.bin: mgetty sendfax newslock \
		login.config mgetty.config sendfax.config 
#
# binaries
#
	-test -d $(BINDIR)  || ( ./mkidirs $(BINDIR)  ; chmod 755 $(BINDIR)  )
	$(INSTALL) -m 755 newslock $(BINDIR)

	-test -d $(SBINDIR) || ( ./mkidirs $(SBINDIR) ; chmod 755 $(SBINDIR) )
	-mv -f $(SBINDIR)/mgetty $(SBINDIR)/mgetty.old
	-mv -f $(SBINDIR)/sendfax $(SBINDIR)/sendfax.old
	$(INSTALL) -s -m 700 mgetty $(SBINDIR)
	$(INSTALL) -s -m 755 sendfax $(SBINDIR)
#
# data files + directories
#
	test -d $(LIBDIR)  || \
		( ./mkidirs $(LIBDIR) &&  chmod 755 $(LIBDIR) )
	test -d $(CONFDIR) || \
		( ./mkidirs $(CONFDIR) && chmod 755 $(CONFDIR))
	test -f $(CONFDIR)/login.config || \
		$(INSTALL) -o root -m 600 login.config $(CONFDIR)/
	test -f $(CONFDIR)/mgetty.config || \
		$(INSTALL) -o root -m 600 mgetty.config $(CONFDIR)/
	test -f $(CONFDIR)/sendfax.config || \
		$(INSTALL) -o root -m 644 sendfax.config $(CONFDIR)/
	test -f $(CONFDIR)/dialin.config || \
		$(INSTALL) -o root -m 600 dialin.config $(CONFDIR)/
	test -f $(CONFDIR)/faxrunq.config || \
		$(INSTALL) -o root -m 644 faxrunq.config $(CONFDIR)/
#
# test for outdated stuff
#
	-@if test -f $(LIBDIR)/mgetty.login ; \
	then \
	    echo "WARNING: the format of $(LIBDIR)/mgetty.login has " ;\
	    echo "been changed. Because of this, to avoid confusions, it's called " ;\
	    echo "$(CONFDIR)/login.config now." ;\
	    echo "" ;\
	fi
#
# fax spool directories
#
	test -d $(spool) || \
		( mkdir $(spool) && chmod 755 $(spool) )
	test -d $(FAX_SPOOL) || \
		( mkdir $(FAX_SPOOL) && \
		  chown $(FAX_OUT_USER) $(FAX_SPOOL) && \
		  chmod 755 $(FAX_SPOOL) )
	test -d $(FAX_SPOOL_IN) || \
		( mkdir $(FAX_SPOOL_IN) && chmod 755 $(FAX_SPOOL_IN) )
	test -d $(FAX_SPOOL_OUT) || \
		  mkdir $(FAX_SPOOL_OUT)
	chown $(FAX_OUT_USER) $(FAX_SPOOL_OUT)
	chmod 755 $(FAX_SPOOL_OUT)
#
# g3 tool programs
#
	cd g3 ; $(MAKE) install INSTALL="$(INSTALL)" \
				BINDIR=$(BINDIR) \
				LIBDIR=$(LIBDIR) CONFDIR=$(CONFDIR)
#
# fax programs / scripts / font file
#
	cd fax ; $(MAKE) install INSTALL="$(INSTALL)" \
				FAX_OUT_USER=$(FAX_OUT_USER) \
				BINDIR=$(BINDIR) SBINDIR=$(SBINDIR) \
				LIBDIR=$(LIBDIR) CONFDIR=$(CONFDIR)
#
# compatibility
#
	if [ ! -z "$(INSTALL_MECHO)" ] ; then \
	    cd compat ; \
	    $(CC) $(CFLAGS) -o mg.echo mg.echo.c && \
	    $(INSTALL) -s -m 755 mg.echo $(BINDIR) ; \
	fi

#
# documentation
#
install.doc:
	cd doc ; $(MAKE) install INSTALL="$(INSTALL)" \
				MAN1DIR=$(MAN1DIR) \
				MAN4DIR=$(MAN4DIR) \
				MAN5DIR=$(MAN5DIR) \
				MAN8DIR=$(MAN8DIR) \
				INFODIR=$(INFODIR)

#
# WWW frontend stuff
#
install.www:
	cd frontends/www ; $(MAKE) install.www INSTALL="$(INSTALL)" \
				BINDIR=$(BINDIR) \
				LIBDIR=$(LIBDIR) CONFDIR=$(CONFDIR)
#
# voice extensions, consult the `voice' chapter in the documentation
#

vgetty:
	@$(MAKE) mgetty
	cd voice; $(MAKE) CFLAGS="$(CFLAGS)" CC="$(CC)" LDFLAGS="$(LDFLAGS)" \
	LN="$(LN)" MV="$(MV)" RM="$(RM)" \
	LIBS="$(LIBS)" \
	FAX_SPOOL_IN="$(FAX_SPOOL_IN)" CONFDIR="$(CONFDIR)" \
	VARRUNDIR="$(VARRUNDIR)" \
	SHELL="$(SHELL)" vgetty-all

vgetty-install: sedscript
	cd voice; $(MAKE) CFLAGS="$(CFLAGS)" CC="$(CC)" LDFLAGS="$(LDFLAGS)" \
	BINDIR="$(BINDIR)" SBINDIR="$(SBINDIR)" LIBDIR="$(LIBDIR)" \
	CONFDIR="$(CONFDIR)" MAN1DIR="$(MAN1DIR)" MAN8DIR="$(MAN8DIR)" INSTALL="$(INSTALL)" \
	PHONE_GROUP="$(PHONE_GROUP)" PHONE_PERMS="$(PHONE_PERMS)" \
	LN="$(LN)" MV="$(MV)" RM="$(RM)" \
	LIBS="$(LIBS)" vgetty-install

install-vgetty: vgetty-install

## test suite
test: bin-all
	for D in g3 t ; do \
	    ( cd $$D ; $(MAKE) CFLAGS="$(CFLAGS) -I.." test ); \
	done

check: test
## misc

dump: logfile.o config.o conf_mg.o goodies.o getdisk.o tio.o gettydefs.o io.o
	$(CC) -o dump -g dump.c logfile.o config.o conf_mg.o goodies.o getdisk.o tio.o gettydefs.o io.o $(LDFLAGS)

######## anything below this line was generated by gcc -MM *.c
cnd.o : cnd.c syslibs.h policy.h mgetty.h ugly.h config.h 
conf_mg.o : conf_mg.c mgetty.h ugly.h policy.h syslibs.h tio.h config.h conf_mg.h 
conf_sf.o : conf_sf.c mgetty.h ugly.h policy.h syslibs.h config.h conf_sf.h 
config.o : config.c syslibs.h mgetty.h ugly.h config.h 
do_chat.o : do_chat.c syslibs.h mgetty.h ugly.h policy.h tio.h 
ring.o: ring.c syslibs.h mgetty.h ugly.h policy.h tio.h
do_stat.o : do_stat.c syslibs.h mgetty.h ugly.h policy.h tio.h 
dump.o : dump.c syslibs.h mgetty.h ugly.h policy.h tio.h fax_lib.h mg_utmp.h \
  config.h conf_mg.h 
faxhng.o : faxhng.c mgetty.h ugly.h 
faxlib.o : faxlib.c mgetty.h ugly.h policy.h fax_lib.h 
faxrec.o : faxrec.c syslibs.h mgetty.h ugly.h tio.h policy.h fax_lib.h 
faxsend.o : faxsend.c syslibs.h mgetty.h ugly.h tio.h policy.h fax_lib.h 
files.o : files.c mgetty.h ugly.h policy.h 
getdisk.o : getdisk.c policy.h mgetty.h ugly.h 
gettydefs.o : gettydefs.c syslibs.h mgetty.h ugly.h policy.h 
goodies.o : goodies.c syslibs.h mgetty.h ugly.h config.h 
io.o : io.c syslibs.h mgetty.h ugly.h 
locks.o : locks.c mgetty.h ugly.h policy.h 
logfile.o : logfile.c mgetty.h ugly.h policy.h 
login.o : login.c mgetty.h ugly.h config.h policy.h mg_utmp.h 
logname.o : logname.c syslibs.h mgetty.h ugly.h policy.h tio.h mg_utmp.h 
mg_m_init.o : mg_m_init.c syslibs.h mgetty.h ugly.h tio.h policy.h fax_lib.h 
mgetty.o : mgetty.c syslibs.h mgetty.h ugly.h policy.h tio.h fax_lib.h mg_utmp.h \
  config.h conf_mg.h 
sendfax.o : sendfax.c syslibs.h mgetty.h ugly.h tio.h policy.h fax_lib.h config.h \
  conf_sf.h 
tio.o : tio.c mgetty.h ugly.h tio.h 
utmp.o : utmp.c mgetty.h ugly.h mg_utmp.h 
