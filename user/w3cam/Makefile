# Generated automatically from Makefile.in by configure.
prefix=/usr/local
exec_prefix=${prefix}
sbindir=${exec_prefix}/sbin
cgibindir=$(prefix)/cgi-bin
bindir=${exec_prefix}/bin

VERSION=0.7.2
CFLAGS += \
	  -DHAVE_LIBM=1 -DHAVE_LIBZ=1 \
	  -DHAVE_LIBPNG=1 \
	  -DHAVE_LIBJPEG=1 \
	  -DVIDEO_DEV=\"/dev/video\" -DVERSION=\"$(VERSION)\"
LIBS = -lpng -ljpeg -lz -lm 

OBJ = w3cam.o cgi.o v4l.o

default: w3cam.cgi vidcat vidcat.1 README ppmtoascii w3camd/w3camd

w3cam.cgi: $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIBS) $(LDLIBS$(LDLIBS_$@))

vidcat: vidcat.o v4l.o
	$(CC) $(LDFLAGS) -o $@ vidcat.o v4l.o $(LIBS) $(LDLIBS$(LDLIBS_$@))

ppmtoascii: ppmtoascii.o
	$(CC) $(LDFLAGS) -o $@ ppmtoascii.o $(LDLIBS$(LDLIBS_$@))

w3camd/w3camd:
	cd w3camd && make

install: w3cam.cgi
	install w3cam.cgi $(cgibindir)/
	test -f $(cgibindir)/w3cam.cgi.scf || \
		install w3cam.cgi.scf $(cgibindir)/
	install vidcat $(bindir)/
	install vidcat.1 $(prefix)/man/man1/

romfs:
	$(ROMFSINST) vidcat /bin/vidcat
	$(ROMFSINST) w3camd/w3camd /bin/w3camd
	$(ROMFSINST) w3cam.cgi /home/httpd/cgi-bin

vidcat.1: vidcat.man
	sed "s/VERSION/$(VERSION)/" < vidcat.man > vidcat.1

clean:
	rm -f *.o w3cam.cgi vidcat ppmtoascii
	cd w3camd && make clean && rm -f w3camd

msproper: clean
	rm -f config.status config.log config.cache Makefile

index.html: index.in
	sed "s/@VERSION@/$(VERSION)/" < $< > $@

README: index.html
	lynx -dump http://www/~rasca/w3cam/index.html | \
		sed "s%/www/%/home.pages.de/%g" > README

tarball: msproper
	cd .. && tar -czvf w3cam-$(VERSION).tar.gz w3cam-$(VERSION)/

