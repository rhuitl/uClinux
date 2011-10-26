SUBDIRS = config tools kdc

EXTRA_DIST = run-tests

check: $(srcdir)/run-tests all
	$(srcdir)/run-tests . @KRB5_BINDIR@
