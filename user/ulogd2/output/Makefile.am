INCLUDES = $(all_includes) -I$(top_srcdir)/include
LIBS=""

SUBDIRS= pcap mysql pgsql sqlite3

pkglib_LTLIBRARIES = ulogd_output_LOGEMU.la ulogd_output_SYSLOG.la \
		     ulogd_output_OPRINT.la ulogd_output_IPFIX.la

ulogd_output_LOGEMU_la_SOURCES = ulogd_output_LOGEMU.c
ulogd_output_LOGEMU_la_LDFLAGS = -module

ulogd_output_SYSLOG_la_SOURCES = ulogd_output_SYSLOG.c
ulogd_output_SYSLOG_la_LDFLAGS = -module

ulogd_output_OPRINT_la_SOURCES = ulogd_output_OPRINT.c
ulogd_output_OPRINT_la_LDFLAGS = -module

ulogd_output_IPFIX_la_SOURCES = ulogd_output_IPFIX.c
ulogd_output_IPFIX_la_LDFLAGS = -module

