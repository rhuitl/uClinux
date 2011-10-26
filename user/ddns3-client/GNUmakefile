#
# ddns3 makefile
#
#	Author: 	Alan Yates <alany@ay.com.au>
#	Version:	$Id: GNUmakefile,v 1.1.1.1 2002/07/19 11:47:20 alany Exp $
#


# system dependent libraries to link
DEFAULT_LIBS=-lcrypt
LINUX_LIBS=-lcrypt
SOLARIS_LIBS=-lcrypt -lsocket -lnsl -lresolv
OPENBSD_LIBS=-lcrypto

# compile magic hacks
SYSTEM=$(shell uname -s | tr "[A-Z]" "[a-z]")
RELEASE=$(shell uname -r)
ifeq ($(SYSTEM),linux)
	LIBS=$(LINUX_LIBS)
endif
ifeq ($(SYSTEM),sunos)
	LIBS=$(SOLARIS_LIBS)
endif
ifeq ($(SYSTEM),openbsd)
	LIBS=$(OPENBSD_LIBS)
endif
ifndef LIBS
	LIBS=$(DEFAULT_LIBS)
endif

all:		ddns3

ddns3:		ddns3.c libddns3.a
	$(CC) $(LDFLAGS) ddns3.c libddns3.a -o ddns3 $(LIBS) $(LDLIBS)

libddns3.a:	sockio.o crypto.o auth.o md5.o ctx.o
	$(AR) -cr libddns3.a *.o
	$(RANLIB) libddns3.a

install:	ddns3
	$(INSTALL) -s ddns3 $(PREFIX)/bin/
	$(INSTALL) ddns3.1 $(PREFIX)/man/man1/

uninstall:
	rm -f $(PREFIX)/bin/ddns3 $(PREFIX)/man/man1/ddns3.1

clean:
	rm -f *.o core *.a ddns3

romfs:
	$(ROMFSINST) /bin/ddns3
