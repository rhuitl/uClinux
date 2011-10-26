noinst_LIBRARIES = libsstr.a
libsstr_a_SOURCES = sstr.c sstr_io.c sstr.h sstr_private.h
EXTRA_DIST = README

all-local:
	rm -f ../../include/sstr.h
	ln -fs ../lib/sstrlib/sstr.h ../../include

distclean-local:
	rm -f ../../include/sstr.h
