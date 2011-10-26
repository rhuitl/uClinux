INCLUDES = -I$(top_builddir)/src/qgen -I$(top_builddir)/src/saal -I.

sbin_PROGRAMS = atmsigd
atmsigd_SOURCES = atmsigd.c io.c io.h kernel.c proto.c proto.h uni.c \
			sap.c sap.h timeout.c timeout.h trace.c trace.h \
			policy.c policy.h cfg_y.y cfg_l.l
atmsigd_XTRAS = mess.o $(top_builddir)/src/qgen/q.out.o \
			$(top_builddir)/src/qgen/qd.dump.o \
			$(top_builddir)/src/lib/libatm.la \
			$(top_builddir)/src/saal/libsaal.a
atmsigd_LDADD = $(atmsigd_XTRAS) -lfl
atmsigd_DEPENDENCIES = mess.c $(atmsigd_XTRAS)

CLEANFILES = mess.c

sysconf_DATA = atmsigd.conf

man_MANS = atmsigd.conf.4 atmsigd.8
EXTRA_DIST = cfg_y.h $(man_MANS) $(sysconf_DATA) mkmess.pl README

mess.c:	$(top_builddir)/src/qgen/uni.h mkmess.pl
	@PERL@ ./mkmess.pl <$(top_builddir)/src/qgen/uni.h >mess.c

