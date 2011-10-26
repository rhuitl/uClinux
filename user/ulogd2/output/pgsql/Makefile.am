
INCLUDES = $(all_includes) -I$(top_srcdir)/include -I$(PQINCPATH)
LIBS=$(PQLIBS)

if HAVE_PGSQL

pkglib_LTLIBRARIES = ulogd_output_PGSQL.la

ulogd_output_PGSQL_la_SOURCES = ulogd_output_PGSQL.c ../../util/db.c
ulogd_output_PGSQL_la_LDFLAGS = -module

endif
