# $Id: Makefile,v 1.16 1994/07/25 15:59:41 gkim Exp $
#
# 	Tripwire build
#
#  See the README file before running this!
#

###
###   Start of user-modified settings
###   Examine these and change the ones that need to be
###   Altered on your system
###

# destination directory for final executables
DESTDIR = /secureplace/bin

# destination for man pages
MANDIR  = /usr/man

# system utilities
LEX	= lex
#LEX	= flex			# For the GNU crowd

YACC	= yacc
#YACC	= bison -y		# For the GNU crowd (make it look like yacc)
#				# see ./contrib/README.linux for tips on
#				# making work.

# for SVR4 make (must be a Bourne-type shell)
SHELL	= /bin/sh
#SHELL	= /bin/ksh		# Another common shell
#SHELL	= /bin/bash		# For the GNU fanatics

# you can use ANSI C if you like, but K&R is equally fine.
#CC     = cc			# common
#CC     = gcc			# also common
#CC	= /usr/ccs/bin/cc	# Pyramid DC/OSx (SVR4)

#CFLAGS = -O			# common 
#CFLAGS = -g 			# common 
#CFLAGS = -g			# debugging
#CFLAGS = -O -cckr		# SGI
#	NOTE: some versions of the HP C compiler optimizer breaks snefru.c!  
#		consider recompiling this file seperately without optimization
#CFLAGS = -O -Aa -N		# HP/UX ansi
#CFLAGS = -O -Ac -N		# HP/UX K&R
#CFLAGS = -O -Ac -N -Wl,-a,archive    # HP/UX K&R, insure archived, static link
#CFLAGS = -systype bsd43	# ETA/10 (SVR3)
#CFLAGS = -systype bsd43	# MIPS RISC/OS 4.5x
#CFLAGS = -O -ansi		# gnu CC
#CFLAGS = -O -ansi -W -Wreturn-type -Wswitch -Wshadow # gnu CC w/all warnings
#CFLAGS = -OG			# Pyramid OSx
#CFLAGS = -O -Kold		# Pyramid DC/OSx (SVR4)
#CFLAGS = -DTW_TYPE32='int'	# DEC OSF/1 Alpha (or any other architecture
                          	# where int [but not long] is a 32 bit quantity)

# a C preprocessor (to build inode.h)
CPP	= $(CC) -E			# common
#CPP	= /usr/lib/cpp		# on older systems
#CPP	= /lib/cpp		# on older systems

# make sure libraries are not linked dynamically (as a security measure)
#LDFLAGS=			# common
#LDFLAGS= -non_shared		# OSF/1
#LDFLAGS= -Bstatic		# SunOS 4 (cannot statically link tripwire
                          	#          on Solaris 2.3)
#LDFLAGS= -dn			# Pyramid DC/OSx (SVR4)

# libraries
#LIBS = 				# common
#LIBS = -lsocket                # SCO
#LIBS = -lmalloc -lsun -lc_s	# IRIX 4.0
#LIBS = -lx			# Xenix
#LIBS = -lbsd			# MIPS RISC/OS
#LIBS = -lgnumalloc           # Encore / UMAX V


# If you don't have the install command, you need to replace
# the use of it later in the makefile with a cp and chmod
INSTALL= /usr/bin/install	# common
#INSTALL= /usr/ucb/install	# Pyramid DC/OSx (SVR4)
#INSTALL= /etc/install		# Pyramid OSx
#INSTALL= /bin/cp		# no install
#INSTALL= /usr/bin/installbsd	# OSF/1 (DEC only?)

# how you get hostname information (BSD vs. SYSV style)
HOSTNAME	= "hostname"		# BSD
#HOSTNAME	= "uname -n"		# System V 


###
###   End of user-modified settings
###   You should not need to change anything after this
###

DIST		= tripwire-1.2

all:
	(cd src; make CC="$(CC)" CFLAGS="$(CFLAGS)" LIBS="$(LIBS)" \
		LDFLAGS="$(LDFLAGS)" CPP="$(CPP)" SHELL=$(SHELL) \
		YACC="$(YACC)" LEX="$(LEX)" all)

install: all
	(cd src; make INSTALL=$(INSTALL) DESTDIR=$(DESTDIR) install)
	(cd man; make INSTALL=$(INSTALL) MANDIR=$(MANDIR) install)

test:	all
	(cd tests; make HOSTNAME=$(HOSTNAME) DIST=$(DIST) SHELL=$(SHELL) \
			CC="$(CC)")

romfs:
	$(ROMFSINST) lib/tw.config-default /etc/default/tw.config
	$(ROMFSINST) -e CONFIG_USER_TRIPWIRE_TRIPWIRE src/tripwire /bin/tripwire
	$(ROMFSINST) -e CONFIG_USER_TRIPWIRE_SIGGEN   src/siggen   /bin/siggen

clean:
	(cd src; make clean)
	(cd man; make clean)
	(cd tests; make clean)
	rm -f core  

clobber: clean
	(cd src; make clobber)
	(cd man; make clean)
	(cd tests; make clean)
	rm -f core  
	rm -f */*_pure_*.o sigs/*/*_pure_*.o

