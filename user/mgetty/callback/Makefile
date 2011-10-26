# Makefile for the "callback" subtree
# of mgetty+sendfax
#
# SCCS: %W% %E% Copyright (c) Gert Doering
#

CC=gcc
CFLAGS=-O2 -I.. -g

zigzag:
	cd .. ; $(MAKE) call-back

all: callback ct

CBOBJS=callback.o conf_cb.o ../config.o ../logfile.o ../do_chat.o \
	../modem.o ../locks.o ../tio.o ../io.o ../goodies.o
CTOBJS=ct.o

callback: $(CBOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o callback $(CBOBJS) $(LIBS)

ct: $(CTOBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ct $(CTOBJS) $(LIBS)

conf_cb.o : conf_cb.c conf_cb.h ../mgetty.h ../ugly.h ../policy.h \
	../syslibs.h ../config.h ../Makefile
	$(CC) $(CFLAGS) -DCONFDIR=\"$(CONFDIR)\" -c conf_cb.c

callback.o: callback.c ../syslibs.h ../mgetty.h ../ugly.h ../policy.h \
	 ../tio.h ../mg_utmp.h ../version.h ../config.h conf_cb.h
	$(CC) $(CFLAGS) -DVARRUNDIR=\"$(VARRUNDIR)\" -c callback.c

clean:
	rm -f *.o

fullclean:
	rm -f *.o callback ct

#
# install programs
#
install: all
	$(INSTALL) -s -m 700 -o root callback $(SBINDIR)
	$(INSTALL) -s -m 4711 -o root ct $(BINDIR)

# source modules
