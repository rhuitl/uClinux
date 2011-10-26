# Generated automatically from Makefile.in by configure.
#
#  Normally You should not need to change anything below
#
include ../Rules.make

CFLAGS+=-I.. -I../libipulog/include -I../include
SH_CFLAGS:=$(CFLAGS) -fPIC

SHARED_LIBS=ulogd_SQLITE3.so

all: $(SHARED_LIBS)

distrib:

$(SHARED_LIBS): %.so: %_sh.o
	$(LD) -shared $(SQLITE3_LDFLAGS) -o $@ $< -lc

%_sh.o: %.c
	$(CC) $(SQLITE3_CFLAGS) $(SH_CFLAGS) -o $@ -c $<
	
clean:
	$(RM) $(SHARED_LIBS) *.o

distclean:
	$(RM) Makefile

install: all
	$(INSTALL) -m 755 -d $(DESTDIR)$(ULOGD_LIB_PATH)
	$(INSTALL) -m 755 *.so $(DESTDIR)$(ULOGD_LIB_PATH)
