# Makefile for the "t/" subtree
# of mgetty+sendfax
#
# CVS: $Id: Makefile,v 1.4 2005/03/16 11:06:59 gert Exp $ Copyright (c) Gert Doering
#

CC=gcc
CFLAGS=-O2 -I.. -g  #-DT_LOG_VERBOSE

TEST_PROGRAMS=t_config t_ring
TEST_SCRIPTS=t_echo t_trap

test: $(TEST_PROGRAMS)
	@for f in $(TEST_PROGRAMS) ; \
	do \
	    echo "run t/$$f..." ; \
	    ./$$f || exit 1 ; \
	done
	@for f in $(TEST_SCRIPTS) ; \
	do \
	    echo "run t/$$f..." ; \
	    rm -f $$f ; ../sedscript <$$f.in >$$f ; chmod +x $$f ; \
	    ./$$f || exit 1 ; \
	done
	@echo "OK"

clean:
	rm -f $(TEST_PROGRAMS)
	rm -f *.o

t_config.o: t_config.c ../mgetty.h ../conf_mg.h ../config.h 

t_ring: t_ring.o ../ring.o ../cnd.o
	$(CC) -o t_ring t_ring.o ../ring.o ../cnd.o $(LDFLAGS)
