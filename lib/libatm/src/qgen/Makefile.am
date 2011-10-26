noinst_PROGRAMS = qgen q.dump # q40.out.o
check_PROGRAMS = q.test

qgen_SOURCES = common.c common.h file.c file.h first.c ql_y.y ql_l.l qgen.c \
		qgen.h second.c third.c
qgen_LDADD = -lfl

q_dump_SOURCES = common.c
q_dump_LDADD = qd.dump.standalone.o
# FIXME: paulsch: We don't really depend on qd.dump.o or q.out.o here, but this
# trick will get it built with only a minor glitch in the dependency checking
# for q.dump.
q_dump_DEPENDENCIES = $(q_dump_LDADD) qd.dump.o q.out.o
EXTRA_q_dump_SOURCES = op.h uni.h qlib.c qlib.h

q_test_SOURCES = qtest.c uni.h
q_test_DEPENDENCIES = q.test.c

#TESTS = $(check_PROGRAMS)

EXTRA_DIST = ql_y.h incl.pl mknl.pl msg.fmt TODO

CLEANFILES = q.out.h q.out.c q.test.c qd.out.h qd.out.c qd.dump.c qd.test.c \
		default.nl # q40.out.h q40.out.c q40.test.c

NLS = atm_ai_msg atm_ai_ie atm_loc atm_cv atm_pu atm_na atm_cond atm_ie \
	atm_msg atm_np atm_ton atm_sat atm_prs atm_scrn atm_vpa atm_poe \
	q2931_cs atm_td atm_bc atm_tc atm_stc atm_upcc q2931_proto atm_flag \
	atm_aalp atm_fd atm_tag atm_l2 atm_l3 atm_tt atm_mc atm_hl atm_imd \
	atm_tdl atm_tni atm_nip atm_shi atm_oci atm_unfm atm_ofi atm_irs \
	atm_it atm_lit atm_lsi atm_tcs atm_css atm_eqo atm_eqp atm_aap \
	atm_asp atm_tor
SYMFILES = uni.h $(shell @PERL@ incl.pl $(CFLAGS) linux/atmsap.h)


default.nl: mknl.pl $(SYMFILES)
	cat $(SYMFILES) | @PERL@ mknl.pl $(NLS) >default.nl || \
	{ rm -f default.nl; echo 1; }

q.out.h q.out.c q.test.c: qgen msg.fmt default.nl
	$(CPP) $(DEFS) - <msg.fmt | ./qgen

#q40.out.h q40.out.c q40.test.c: qgen uni40 default.nl
#	$(CPP) $(DEFS) - <uni40 | PREFIX=q40 ./qgen

qd.out.h qd.out.c qd.dump.c: qgen msg.fmt default.nl
	$(CPP) $(DEFS) - <msg.fmt | ./qgen -D

q.out.o: q.out.c q.out.h qlib.c qlib.h
	$(CC) $(DEFS) $(CFLAGS) -c q.out.c

#q40.out.o: q40.out.c q40.out.h qlib.c qlib.h
#	$(CC) -DUNI40 $(CFLAGS) -c q40.out.c

qd.dump.o: qd.dump.c qd.out.c qlib.c qlib.h
	$(CC) $(DEFS) $(CFLAGS) -c qd.dump.c

qd.dump.standalone.o: qd.dump.c qd.out.c qlib.c qlib.h
	$(CC) $(DEFS) -DSTANDALONE $(CFLAGS) -c qd.dump.c \
	-o qd.dump.standalone.o

