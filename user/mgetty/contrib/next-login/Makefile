#
# Copyright (c) 1988 Regents of the University of California.
# All rights reserved.
#
# Redistribution and use in source and binary forms are permitted
# provided that the above copyright notice and this paragraph are
# duplicated in all such forms and that any documentation, advertising
# materials, and other materials related to such redistribution and
# use acknowledge that the software was developed by the University
# of California, Berkeley.  The name of the University may not be
# used to endorse or promote products derived from this software
# without specific prior written permission.  THIS SOFTWARE IS PROVIDED
# ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND
# FITNESS FOR A PARTICULAR PURPOSE.
#
# from @(#)Makefile	5.3 (Berkeley) 5/9/89
#

CFLAGS=        -O -bsd -DORIGINAL -DFIX8BIT
LIBC=	/lib/libsys_s.a
SRCS=	login.c setenv.c
OBJS=	login.o setenv.o
MAN=	login.0
DESTDIR= /usr/local

all: login

login: ${LIBC} ${OBJS}
	${CC} -object -o $@ -s ${OBJS}

setenv.o: setenv.c
	${CC} ${CFLAGS} -DLIBC_SCCS -c $<

clean:
	rm -f ${OBJS} core login

cleandir: clean
	rm -f ${MAN} tags .depend

depend: ${SRCS}
	mkdep -p ${CFLAGS} ${SRCS}

install:
	install -s -o root -g bin -m 4755 login ${DESTDIR}/bin/modem-login

lint: ${SRCS}
	lint ${CFLAGS} ${SRCS}

tags: ${SRCS}
	ctags ${SRCS}
