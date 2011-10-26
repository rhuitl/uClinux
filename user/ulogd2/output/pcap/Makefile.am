
INCLUDES = $(all_includes) -I$(top_srcdir)/include $(PCAP_INC)
LIBS=$(PCAP_LIB)

if HAVE_PCAP

pkglib_LTLIBRARIES = ulogd_output_PCAP.la

ulogd_output_PCAP_la_SOURCES = ulogd_output_PCAP.c
ulogd_output_PCAP_la_LDFLAGS = -module

endif
