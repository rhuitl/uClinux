## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

#INCLUDES = -I../include

lib_LTLIBRARIES = libsf_engine.la

libdir = ${exec_prefix}/lib/snort_dynamicengine

libsf_engine_la_LDFLAGS = -module

libsf_engine_la_SOURCES = \
bmh.c \
bmh.h \
sf_snort_detection_engine.c \
sf_snort_packet.h \
sf_snort_plugin_api.c \
sf_snort_plugin_api.h \
sf_snort_plugin_byte.c \
sf_snort_plugin_content.c \
sf_snort_plugin_hdropts.c \
sf_snort_plugin_loop.c \
sf_snort_plugin_pcre.c \
sf_snort_plugin_rc4.c \
sfghash.c \
sfhashfcn.c

sfghash.c: ../../sfutil/sfghash.c
	cp $? $@

sfhashfcn.c: ../../sfutil/sfhashfcn.c
	cp $? $@

SUBDIRS = examples
