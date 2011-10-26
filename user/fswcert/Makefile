###################################################
# Adjust SSLDIR before make ...
SSLDIR=$(ROOTDIR)/lib/libssl

# Adjust IPSECDIR before make install ...
IPSECDIR=$(ROOTDIR)/romfs/bin

###################################################

VERSION = 0.6

CFLAGS += -Wall -DVERSION=\"$(VERSION)\" -I$(SSLDIR)/include
LDFLAGS += -L$(SSLDIR)
EXTRA_LDLIBS = -lcrypto

DISTFILES=Makefile README CHANGES fswcert.c _confread.patch

all : fswcert

fswcert : fswcert.o
	$(CC) $(LDFLAGS) -o fswcert fswcert.o $(EXTRA_LDLIBS) $(LDLIBS)

fswcert.o: fswcert.c
	$(CC) $(CFLAGS) -c fswcert.c

romfs:
	$(ROMFSINST) /bin/fswcert

clean :
	rm -f fswcert fswcert.o

dist :
	DIR=$$(pwd | sed -e 's,^.*/\([^/]*\)$$,\1,') ; \
	cd .. ; \
	tar cvfz $$DIR-$(VERSION).tar.gz $(DISTFILES:%=$$DIR/%)

install :
	mkdir -p $(IPSECDIR)
	install --strip fswcert $(IPSECDIR)
	mkdir -pm 700 /etc/ipsec.d/cacerts
	mkdir -pm 700 /etc/ipsec.d/crls
