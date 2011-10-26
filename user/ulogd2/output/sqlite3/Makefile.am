INCLUDES = $(all_includes) -I$(top_srcdir)/include $(SQLITE3_INC)
LIBS=$(SQLITE3_LIB)

if HAVE_SQLITE3

pkglib_LTLIBRARIES = ulogd_output_SQLITE3.la

ulogd_output_SQLITE3_la_SOURCES = ulogd_output_SQLITE3.c ../../util/db.c
ulogd_output_SQLITE3_la_LDFLAGS = -module

endif
