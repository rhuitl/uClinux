CFLAGS	+= -I.. -I../../include -Itacc/include
INSTALL	= install

ifeq ($(CONFIG_USER_PPPD_WITH_DYNAMIC_PLUGINS),y)
CFLAGS  += -fPIC -DDYNAMIC_PLUGINS=1
LDFLAGS = -shared
SO = so
else
SO = o
endif

DESTDIR = $(INSTROOT)@DESTDIR@
BINDIR = $(DESTDIR)/sbin
MANDIR = $(DESTDIR)/share/man/man8
LIBDIR = $(DESTDIR)/lib/pppd/$(VERSION)

SUBDIRS := 
ifeq ($(CONFIG_USER_PPPD_WITH_PPPOE),y)
SUBDIRS += rp-pppoe
endif
ifeq ($(CONFIG_USER_PPPD_WITH_PPPOA),y)
SUBDIRS += pppoatm
endif
ifeq ($(CONFIG_USER_PPPD_WITH_RADIUS),y)
SUBDIRS += radius
endif

PLUGINS := 
ifeq ($(CONFIG_USER_PPPD_WITH_MINCONN),y)
PLUGINS += minconn.$(SO)
endif
ifeq ($(CONFIG_USER_PPPD_WITH_PASSPROMPT),y)
PLUGINS += passprompt.$(SO)
endif
ifeq ($(CONFIG_USER_PPPD_WITH_PASSWORDFD),y)
PLUGINS += passwordfd.$(SO)
endif
ifeq ($(CONFIG_USER_PPPD_WITH_WINBIND),y)
PLUGINS += winbind.$(SO)
endif

ifeq ($(CONFIG_USER_PPPD_WITH_TACACS),y)
PLUGINS += tacacs.$(SO)
SUBDIRS += tacc/lib
endif

# include dependencies if present
ifeq (.depend,$(wildcard .depend))
include .depend
endif

all:	$(PLUGINS)
	for d in $(SUBDIRS); do $(MAKE) $(MFLAGS) -C $$d all; done

%.so: %.c
	$(CC) -o $@ $(LDFLAGS) $(CFLAGS) $^

VERSION = $(shell awk -F '"' '/VERSION/ { print $$2; }' ../patchlevel.h)

install: $(PLUGINS)
	$(INSTALL) -d $(LIBDIR)
	$(INSTALL) $? $(LIBDIR)
	for d in $(SUBDIRS); do $(MAKE) $(MFLAGS) -C $$d install; done

clean:
	rm -f *.o *.so *.a
	for d in $(SUBDIRS); do $(MAKE) $(MFLAGS) -C $$d clean; done

depend:
	$(CPP) -M $(CFLAGS) *.c >.depend
	for d in $(SUBDIRS); do $(MAKE) $(MFLAGS) -C $$d depend; done
