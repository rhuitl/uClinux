AM_CFLAGS = @KRB5_CFLAGS@ @KRB4_CFLAGS@

securitydir = $(libdir)/security
security_LTLIBRARIES = pam_krb5.la
noinst_LTLIBRARIES = libpam_krb5.la
pkgsecuritydir = $(libdir)/security/$(PACKAGE)
pkgsecurity_PROGRAMS = pam_krb5_storetmp
EXTRA_DIST = afs5log.1 pam_krb5.5 pam_krb5.8 pam_krb5_storetmp.8 pam_newpag.5 pam_newpag.8
noinst_PROGRAMS = harness harness-newpag shmcat
man_MANS = pam_krb5.5 pam_krb5.8 pam_krb5_storetmp.8
noinst_MANS =
if AFS
noinst_LTLIBRARIES += pam_newpag.la
noinst_MANS += pam_newpag.5 pam_newpag.8
endif
bin_PROGRAMS =

if AFS
bin_PROGRAMS += afs5log
man_MANS += afs5log.1
noinst_PROGRAMS += pagsh
endif

if WITH_DIRECT_LIBPAM
DIRECT_LIBPAM = -lpam
else
DIRECT_LIBPAM =
endif

libpam_krb5_la_SOURCES = \
	conv.c \
	conv.h \
	init.c \
	init.h \
	initopts.c \
	initopts.h \
	items.c \
	items.h \
	kuserok.c \
	kuserok.h \
	minikafs.h \
	perms.c \
	perms.h \
	prompter.c \
	prompter.h \
	shmem.c \
	shmem.h \
	stash.c \
	stash.h \
	storetmp.c \
	storetmp.h \
	xstr.c \
	xstr.h \
	v4.c \
	v4.h \
	v5.c \
	v5.h
	
pam_krb5_la_LDFLAGS = -avoid-version -export-dynamic -module -export-symbols-regex 'pam_sm.*' @SYMBOLIC_LINKER_FLAG@
pam_krb5_la_LIBADD = libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@ $(DIRECT_LIBPAM)
pam_krb5_la_SOURCES = \
	log.c \
	log.h \
	map.c \
	map.h \
	options.c \
	options.h \
	tokens.h \
	userinfo.c \
	userinfo.h \
	auth.c \
	acct.c \
	password.c \
	session.c \
	sly.c \
	sly.h

pam_newpag_la_LDFLAGS = -avoid-version -export-dynamic -module -export-symbols-regex 'pam_sm.*' @SYMBOLIC_LINKER_FLAG@
pam_newpag_la_LIBADD = libpam_krb5.la @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@
pam_newpag_la_SOURCES = \
	pam_newpag.c \
	log.c \
	log.h \
	minikafs.h \
	options.c \
	options.h

pam_krb5_storetmp_SOURCES = \
	pam_krb5_storetmp.c
pam_krb5_storetmp_LIBS =
pam_krb5_storetmp_LDADD = xstr.lo

afs5log_SOURCES = \
	afs5log.c \
	logstdio.c \
	logstdio.h \
	log.h
afs5log_LDADD = libpam_krb5.la @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

pagsh_SOURCES = \
	pagsh.c \
	logstdio.c \
	logstdio.h \
	log.h
pagsh_LDADD = libpam_krb5.la @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

harness_SOURCES = harness.c
harness_LDADD = \
	auth.lo \
	acct.lo \
	password.lo \
	session.lo \
	logstdio.lo \
	map.lo \
	options.lo \
	perms.lo \
	userinfo.lo \
	sly.lo \
	v4.lo \
	v5.lo
harness_LDADD += libpam_krb5.la @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

harness_newpag_SOURCES = harness.c \
	pam_dummy_acct.c \
	pam_dummy_chauthtok.c
harness_newpag_LDADD = \
	pam_newpag.lo \
	logstdio.lo \
	options.lo \
	perms.lo \
	v4.lo \
	v5.lo
harness_newpag_LDADD += libpam_krb5.la @PAM_LIBS@ @KRB5_LIBS@ @KRB4_LIBS@ @KEYUTILS_LIBS@

shmcat_SOURCES = shmcat.c
shmcat_LDADD = logstdio.lo libpam_krb5.la @PAM_LIBS@

if AFS
pam_krb5_la_SOURCES += tokens.c
libpam_krb5_la_SOURCES += minikafs.c
harness_LDADD += minikafs.lo tokens.lo
else
libpam_krb5_la_SOURCES += noafs.c
endif
