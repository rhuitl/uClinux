
CFLAGS +=	-D'VERSION="$(VERSION)"'

VERSION =	2.0.0-beta5
TAR =		pop3proxy-$(VERSION)
DIR =		pop3proxy-$(VERSION)

TARGETS =	pop3.proxy

POP3PROXY=	main.o pop3.o clamav.o procinfo.o ip-lib.o lib.o


all:		$(TARGETS)
	-ctags *.[ch]


install:	all
	strip $(TARGETS)
	cp $(TARGETS) /usr/local/sbin
	cp *.1 /usr/local/man/man1


romfs:
	$(ROMFSINST) /bin/pop3.proxy


pop3.proxy:	$(POP3PROXY)
	$(CC) -o $@ $+



tar:		clean
	cd ..; tar cvf $(TAR).tar $(DIR); gzip $(TAR).tar
	mv ../$(TAR).tar.gz .
	
clean:
	-rm -f *.o cut out $(TARGETS) $(TAR).tar.gz

