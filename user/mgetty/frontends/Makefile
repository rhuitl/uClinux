#
# Actually, this makefile doesn't do anything except calling others...
#
SUBDIRS=dialog tkperl

all:
	for i in $(SUBDIRS) ; do \
	    ( cd $$i ; $(MAKE) all ); \
	done

install:
	for i in $(SUBDIRS) ; do \
	    ( cd $$i ; $(MAKE) BINDIR=\"$(BINDIR)\" SBINDIR=\"$(SBINDIR)\" \
			       LIBDIR=\"$(LIBDIR)\" install ); \
	done

clean:
	for i in $(SUBDIRS) ; do \
	    ( cd $$i ; $(MAKE) clean ); \
	done

fullclean:
	for i in $(SUBDIRS) ; do \
	    ( cd $$i ; $(MAKE) fullclean ); \
	done
