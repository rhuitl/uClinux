
INCLUDES = $(all_includes) -I$(top_srcdir)/include
CPPFLAGS = -DULOGD_CONFIGFILE=\"$(prefix)/etc/ulogd.conf\"

sbin_PROGRAMS = ulogd

ulogd_SOURCES = ulogd.c select.c timer.c conffile.c
ulogd_LDFLAGS = -export-dynamic
