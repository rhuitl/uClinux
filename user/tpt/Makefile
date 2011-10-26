# $Header: /cvs/sw/new-wave/user/tpt/Makefile,v 1.2 2002-05-02 14:04:20 gerg Exp $

CFLAGS+=-Wall -Wshadow

OFILES = tpt.o util.o build.o dump.o massage.o

tpt: $(OFILES)

romfs:
	$(ROMFSINST) /bin/tpt

$(OFILES): tpt.h

clean:
	rm -f $(OFILES) tpt
