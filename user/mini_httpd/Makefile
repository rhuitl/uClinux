# Makefile for mini_httpd, hacked for Lineo NETtel environment

ifdef CONFIG_USER_MINI_HTTPD_WITH_SSL
CFLAGS += -DUSE_SSL
EXTRALIBS += $(LIBSSL) $(LIBCRYPTO) #-lRSAglue
endif

#CFLAGS += -DUSE_IPV6
#LDLIBS += -L/usr/local/v6/lib -linet6

#CFLAGS  += -g
#LDFLAGS += -g

CFLAGS  += -MD

EXTRALIBS += $(LIBCRYPT)

all: mime_types.h mini_httpd htpasswd

mini_httpd: mini_httpd.o tdate_parse.o
	$(CC) $(LDFLAGS) -o $@ $^ $(EXTRALIBS) $(LDLIBS)

mime_types.h: mime_types.txt
	rm -f mime_types.h
	sed < mime_types.txt > mime_types.h \
	  -e 's/#.*//' -e 's/[ 	]*$$//' -e '/^$$/d' \
	  -e 's/[ 	][ 	]*/", "/' -e 's/^/{ "/' -e 's/$$/" },/'

htpasswd: htpasswd.o
	$(CC) $(LDFLAGS) -o $@ $^ $(EXTRALIBS) $(LDLIBS)

clean:
	-rm -f mini_httpd mime_types.h htpasswd *.o

romfs:
	$(ROMFSINST) /bin/mini_httpd

-include *.d
