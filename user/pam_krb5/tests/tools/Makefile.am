testdir = `cd $(builddir); /bin/pwd`

EXTRA_DIST = klist_a.in klist_c.in klist_f.in klist_t.in klist_4.in

noinst_PROGRAMS = pam_harness

pam_harness_SOURCES = pam_harness.c
pam_harness_LDADD = -lpam -ldl
