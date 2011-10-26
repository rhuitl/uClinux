SUBDIRS = @LIBIPTC_DIR@ sstrlib
DIST_SUBDIRS = libiptc sstrlib

all-local:
	rm -f libsstr.a libiptc.a
	ln -fs sstrlib/libsstr.a libiptc/libiptc.a .

clean-local:
	rm -f libsstr.a libiptc.a
