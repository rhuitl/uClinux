-include ../user.mak

#CFLAGS=-Os -fomit-frame-pointer
VERSION=$(shell head -1 CHANGES|sed 's/://')
CFLAGS += -Wall
CFLAGS += -DFNORD=\"fnord/$(VERSION)\"
CFLAGS += -DCGI -DLOG_TO_SYSLOG -DSTATIC_ERRORS=\"/error/%ld.html\"
FLTFLAGS += -s 15000

# CFLAGS += -DUSE_SENDFILE

# For debugging...
#LDLIBS=$(SLIBC)
#CFLAGS += -g -DDEBUG

OBJS += httpd.o

ifdef CONFIG_PROP_FNORD_SECURITY_COUNT
CFLAGS += -DSECURITY_COUNTS
endif
ifdef CONFIG_USER_FNORD_404_REDIR
CFLAGS += -DAUTO_REDIRECT
endif

ifndef CONFIG_USER_FNORD_NOAUTH
# These are for auth
CFLAGS += -DUSE_AUTH
OBJS += auth.o base64.o
ifdef CONFIG_USER_FNORD_PAM
CFLAGS += -DAUTH_PAM
AUTHLIBS := -lpam -lpam_misc -ldl
endif
endif

all: httpd

httpd: $(OBJS) libowfat.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBCRYPT) $(AUTHLIBS) $(LDLIBS)

libowfat.a: httpd.o buffer_1.o buffer_puts.o buffer_flush.o buffer_put.o \
buffer_putulong.o buffer_2.o buffer_putspace.o buffer_stubborn.o \
buffer_putflush.o str_copy.o fmt_ulong.o byte_diff.o byte_copy.o \
str_len.o str_diff.o str_chr.o str_diffn.o str_start.o scan_ulong.o
	$(AR) cru $@ $^
	-$(RANLIB) $@

.PHONY: rename clean install server
server:
	./httpd -p 8000 -l default

install: httpd
	rm -f /usr/local/bin/fnord
	cp httpd /usr/local/bin/fnord

clean:
	rm -f *.[oa] httpd fnord fnord-cgi fnord-idx
	rm -f *.gdb *.elf

#install:
	#test -d /command || mkdir /command

CURNAME=$(notdir $(shell pwd))
VERSION=fnord-$(shell head -n 1 CHANGES|sed 's/://')

tar: rename
	cd .. && tar cvvf $(VERSION).tar.bz2 --use=bzip2 --exclude CVS --exclude bin-* --exclude .cvsignore --exclude default $(VERSION)

romfs:
	$(ROMFSINST) /bin/httpd
ifndef CONFIG_PROP_CONFIG_LIBCONFIG
ifndef CONFIG_USER_CGI_HTTPS_ONLY
	$(ROMFSINST) -a "80 stream tcp nowait root /bin/httpd /home/httpd" -A "80 stream" /etc/default/inetd.conf
endif
ifdef CONFIG_USER_SSLWRAP_SSLWRAP
	$(ROMFSINST) -a "443 stream tcp nowait root /bin/sslwrap -cert /etc/config/ssl_cert.pem -key /etc/config/ssl_key.pem -exec /bin/httpd /home/httpd" \
		-A "443 stream" /etc/default/inetd.conf
endif
endif
