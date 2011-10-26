AUTOMAKE_OPTIONS = ../ansi2knr

inetdaemondir = @inetdaemondir@

inetdaemon_PROGRAMS = @ftpd_BUILD@

EXTRA_PROGRAMS = ftpd

ftpd_SOURCES = ftpcmd.y ftpd.c logwtmp.c popen.c pam.c auth.c \
               conf.c server_mode.c

noinst_HEADERS = extern.h

man_MANS = ftpd.8

@PATHDEFS_MAKE@

INCLUDES = $(PATHDEF_FTPWELCOME) $(PATHDEF_FTPUSERS) \
           $(PATHDEF_FTPLOGINMESG) $(PATHDEF_FTPCHROOT) $(PATHDEF_FTPDPID) \
           $(PATHDEF_DEVNULL)  $(PATHDEF_NOLOGIN) $(PATHDEF_BSHELL) -I$(top_builddir)/include

LIBCRYPT = @LIBCRYPT@
LIBWRAP = @LIBWRAP@
LIBPAM = @LIBPAM@
LIBLS = @LIBLS@

LDADD = $(LIBLS) -L../libinetutils -linetutils $(LIBCRYPT) $(LIBWRAP) $(LIBPAM)

EXTRA_DIST = $(man_MANS) ftpcmd.c
