## Makefile for Net Tamagotchi
##
## ff@lagged.net, algernon@debian.org

VERSION		= 1.2.0

#CC		= gcc
INSTALL		= install
INSTALL_PROGRAM	= ${INSTALL} -m 0755
INSTALL_DATA	= ${INSTALL} -m 0644

CFLAGS		= -ansi -pedantic -Wall -O2 -g

prefix		= /usr/local
exec_prefix	= ${prefix}
gamesdir	= ${exec_prefix}/games
mandir		= ${prefix}/man
man6dir		= ${mandir}/man6

## You probably don't need to modify anything below this
##----------------------------------------------------##

SHELL		= /bin/sh
srcdir		= .

CPPFLAGS	= -DVERSION=\"${VERSION}\"

SOURCES		= api.c exec.c list.c main.c status.c
OBJS		= ${SOURCES:.c=.o}

PROG		= tamad
MAN		= tamad.6
DISTFILES	= CHANGES COPYING INSTALL Makefile tama.h ${SOURCES} ${MAN}
DISTFILES_SUB	= contrib/tama contrib/tama-nanny.exp contrib/tama.6

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o ${PROG} ${OBJS} $(LDLIBS$(LDLIBS_$@))

%.o: ${srcdir}/%.c tama.h
	${CC} ${CPPFLAGS} ${CFLAGS} -c $< -o $@

install: installdirs ${PROG}
	${INSTALL_PROGRAM} ${PROG} ${DESTDIR}${gamesdir}/
	${INSTALL_DATA} ${srcdir}/${MAN} ${DESTDIR}${man6dir}/

install-strip:
	${MAKE} INSTALL_PROGRAM='${INSTALL_PROGRAM} -s' install

installdirs:
	${INSTALL} -d ${DESTDIR}${gamesdir}
	${INSTALL} -d ${DESTDIR}${man6dir}

uninstall:
	rm -f ${gamesdir}/${PROG}
	rm -f ${man6dir}/${MAN}

clean distclean mostlyclean maintainer-clean:
	rm -f ${PROG} ${OBJS} *.core core *.bak *~

dist:
	${INSTALL} -d tama-${VERSION} tama-${VERSION}/contrib
	cp -pR ${DISTFILES} tama-${VERSION}/
	cp -pR ${DISTFILES_SUB} tama-${VERSION}/contrib/
	tar -cf - tama-${VERSION} | gzip -9 >tama-${VERSION}.tar.gz
	rm -rf tama-${VERSION}

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all install installdirs install-strip uninstall clean \
	distclean mostlyclean maintainer-clean dist

romfs:
	$(ROMFSINST) /bin/tamad
