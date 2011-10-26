#
#CC=cc

SOURCES= README Makefile LICENSE plug.1 plug.c plug.h config.h

#CFLAGS=-Os
#LIBS= 

all: plug #plug.man

plug: plug.o
	$(CC) $(LDFLAGS) plug.o -o plug $(LDLIBS)

plug.o: plug.h config.h plug.c Makefile

plug.man: plug.1
	nroff -man plug.1 > plug.man

clean:
	rm -f plug plug.o plug.man plug.gdb

plug.shar: $(SOURCES)
	shar $(SOURCES) > plug.shar

plug.tgz: $(SOURCES)
	tar cvf - $(SOURCES) | gzip > plug.tgz

romfs:
	$(ROMFSINST) /bin/plug
