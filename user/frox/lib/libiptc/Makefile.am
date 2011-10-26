noinst_LIBRARIES = libiptc.a
libiptc_a_SOURCES = libip4tc.c ipt_kernel_headers.h libiptc.h
EXTRA_libiptc_a_SOURCES = libiptc.c
EXTRA_DIST = README

INCLUDES = -DNETFILTER_VERSION=\"1.2\"

all-local:
	rm -f ../../include/ipt_kernel_headers.h ../../include/libiptc.h
	ln -fs ../lib/libiptc/ipt_kernel_headers.h ../../include
	ln -fs ../lib/libiptc/libiptc.h ../../include

distclean-local:
	rm -f ../../include/ipt_kernel_headers.h ../../include/libiptc.h
