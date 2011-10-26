.PRECIOUS: %.o %_sh.o

ifndef $(KSRC)
KSRC := $(ROOTDIR)/$(LINUXDIR)
endif

SBIN := $(DESTDIR)/sbin
LIBDIR := $(DESTDIR)/lib
MANDIR := $(DESTDIR)/usr/man
CC := gcc 
CFLAGS += -Wall -O2 -I $(KSRC)/include -I../include $(XCFLAGS) -fPIC -DLIBDIR=\"$(LIBDIR)\"

SH_CFLAGS := $(CFLAGS) -fPIC
LIBMASQ := ip_masq
LDLIBS := $(XLDFLAGS) -ldl -l$(LIBMASQ) $(LDLIBS)
LDFLAGS += -L../lib
SH_LDLIBS := $(XLDFLAGS) -ldl -l$(LIBMASQ) $(SH_LDLIBS)
SH_LDFLAGS += -L../lib
