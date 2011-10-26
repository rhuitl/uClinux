## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_dns_preproc.la

libsf_dns_preproc_la_LDFLAGS = -module

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c 

nodist_libsf_dns_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c 

libsf_dns_preproc_la_SOURCES = \
spp_dns.c \
spp_dns.h \
sf_preproc_info.h

EXTRA_DIST = \
sf_dns.dsp

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

all-local:
	$(MAKE) DESTDIR=$(PWD)/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c
