# $Id: Makefile,v 1.14 1993/12/15 23:03:40 genek Exp $
#
# 	Tripwire test

DIST=tripwire-1.1
SIGGEN=../src/siggen
TESTDIR=./testfiles
TEMPFILE=@@TRIPWIRE_TEST.0
TEST0KEY=test0.key
HOSTNAME=

all:	OKSIGS test

OKSIGS:	$(SIGGEN) createfiles
	$(SHELL) test0.sh $(SIGGEN) $(TESTDIR) $(TEMPFILE) $(TEST0KEY)
	@rm -rf $(TESTDIR)/t_file*

createfiles:	createfiles.c
	@$(CC) $(CFLAGS) -o createfiles createfiles.c $(LIBS)

OKEXER:
	@$(SHELL) test.twpre.sh
	@$(SHELL) test.update.sh
	@$(SHELL) test.inter.sh
	@$(SHELL) test.escape.sh
	@rm -rf databases
	@touch OKEXER

test:	../src/tripwire OKSIGS OKEXER
	@HOST=`echo $(HOSTNAME)`; \
	CURRPATH=`pwd`;	\
	$(SHELL) test1.sh "$(HOSTNAME)" $(DIST)

../src/tripwire:
	(cd ..; make all)

clean:
	rm -f tw.db_TEST.@ @tw.config createfiles $(TEMPFILE) OKSIGS $(TESTDIR)/t_file* OKEXER

clobber:	clean

