# Makefile for the "g3 tools" subtree
# of mgetty+sendfax
#
# SCCS: $Id: Makefile,v 4.6 2005/02/27 19:02:16 gert Exp $ Copyright (c) Gert Doering
#

CC=gcc
CFLAGS=-O2 -I.. -g 

G3_PROGRAMS=pbm2g3 g3cat g32pbm sff2g3

all: $(G3_PROGRAMS)

pbm2g3: pbm2g3.o g3.o run_tbl.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o pbm2g3 pbm2g3.o g3.o run_tbl.o $(LIBS)

g32pbm: g32pbm.o g3.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o g32pbm g32pbm.o g3.o $(LIBS)

g3cat: g3cat.o g3.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o g3cat g3cat.o g3.o $(LIBS)

sff2g3: sff2g3.o g3.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o sff2g3 sff2g3.o g3.o $(LIBS)

g3.o : g3.c g3.h ../ugly.h
g3cat.o : g3cat.c g3.h ../ugly.h 
g32pbm.o : g32pbm.c g3.h ../ugly.h
pbm2g3.o : pbm2g3.c g3.h ../ugly.h
run_tbl.o : run_tbl.c ../ugly.h 

clean:
	rm -f *.o

fullclean:
	rm -f *.o $(G3_PROGRAMS)

install: all
#
# install programs
#
	for f in $(G3_PROGRAMS) ; do \
		$(INSTALL) -s -m 755 $$f $(BINDIR) ; \
	done
#
# make symlink for "g3topbm" (so third-party fax viewers won't fail)
#
	-cd $(BINDIR) ; \
	test -x g3topbm || ln -s g32pbm g3topbm


# test suite
test:
	@echo "create G3 test file (diagonal line) 'test.g3'..."
	@awk 'BEGIN \
	       { printf "P1\n1728 1728\n"; \
		 for(i=0;i<1728;i++)        \
		 { for(j=0;j<i;j++) { printf "0 " }; printf "1 "; \
		   for(j=i+1;j<1728;j++) { printf "0 " } ; printf "\n"; } }' \
		       /dev/null | ./pbm2g3 >test.g3
	@echo "compare to reference file 'test-ref.g3'..."
	cmp test.g3 test-ref.g3

# g3cat
	@echo 'testing g3cat file...'
	./g3cat test-ref.g3 >test.g3
	cmp test-ref.g3 test.g3
	@echo 'testing g3cat - (stdin)...'
	./g3cat - <test-ref.g3 >test.g3
	cmp test-ref.g3 test.g3

# pbm2g3/g32pbm
	@echo 'testing g32pbm file | pbm2g3 >test.g3...'
	./g32pbm test-ref.g3 | ./pbm2g3 >test.g3

# -r (1) -> result must be different
	@echo 'testing pbm2g3 -r...'
	./g32pbm test-ref.g3 | ./pbm2g3 -r >test.g3
	if cmp test-ref.g3 test.g3 >/dev/null ; then \
		echo 'g32pbm <in | pbmg3 -r >out identical!' >&2 ; exit 1; \
	        else true ; fi

# -r (2) -> converting twice must give identical result
	@echo 'testing pbm2g3 -r | g32pbm -r...'
	./g32pbm test-ref.g3 | ./pbm2g3 -r | ./g32pbm -r | ./pbm2g3 >test.g3
	cmp test-ref.g3 test.g3

# -h option to g3cat and pbm2g3
	@echo 'testing pbm2g3 -h 10 and g3cat -h 10...'
	./g32pbm test-ref.g3 | ./pbm2g3 -h 10 >test-1.g3
	./g3cat -h 10 test-ref.g3 >test-2.g3
	cmp test-1.g3 test-2.g3

# g3cat puts 2 white lines between files, so "g3cat -h 10" or
# "g3cat 8-wite-lines.file" should have same result
	@echo
	@echo 'testing g3cat with stdin+file vs. g3cat -h...'
	( echo "P1 1 8" ; echo "0 0 0 0 0 0 0 0" ) | ./pbm2g3 | \
	     ./g3cat - test-ref.g3 >test-1.g3
	./g3cat -h 10 test-ref.g3 >test-2.g3
	cmp test-1.g3 test-2.g3

# g3cat with -a (align EOL), -p (minimum byte padding for each line), -R
	@echo
	@echo 'testing g3cat -a / -R / -p <padding>...'
	( echo "P1 1 10" ; echo "0 0 0 0 0 0 0 0 0 0" ) | ./pbm2g3 >test.g3
	test `cat test.g3 | wc -c` = 47
	test `./g3cat test.g3 | wc -c` = 47
	test `./g3cat -a test.g3 | wc -c` = 54
	test `./g3cat -a -R test.g3 | wc -c` = 42
	test `./g3cat -p 5 -a -R test.g3 | wc -c` = 52
	test `./g3cat -p 10 -a -R test.g3 | wc -c` = 102
	test `./g3cat -p 100 -a -R test.g3 | wc -c` = 1002
	test `./g3cat -p 100 -a test.g3 | ./g3cat - | wc -c` = 47

	@echo
	@echo 'testing g3cat -L <length> / -w <width>....'
	test "`./g3cat -L 10   test-ref.g3 |./g32pbm |sed -n 2p`" = "1728 10"
	test "`./g3cat -L 100  test-ref.g3 |./g32pbm |sed -n 2p`" = "1728 100"
	test "`./g3cat -L 1000 test-ref.g3 |./g32pbm |sed -n 2p`" = "1728 1000"
	test "`./g3cat -L 2000 test-ref.g3 |./g32pbm |sed -n 2p`" = "1728 1728"
	test "`./g3cat -L 1000 -w 1000 test-ref.g3 2>/dev/null |./g32pbm |sed -n 2p`" = "1000 1000"

	@echo "all G3 program tests passed!"
	@rm test.g3 test-1.g3 test-2.g3

