## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_ssh_preproc.la

libsf_ssh_preproc_la_LDFLAGS = -module

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c 

nodist_libsf_ssh_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c 

libsf_ssh_preproc_la_SOURCES = \
spp_ssh.c \
spp_ssh.h \
sf_preproc_info.h

EXTRA_DIST = \
sf_ssh.dsp

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

all-local:
	$(MAKE) DESTDIR=$(PWD)/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c
