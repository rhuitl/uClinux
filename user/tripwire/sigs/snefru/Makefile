# $Id: Makefile,v 1.3 1993/11/22 06:38:25 genek Exp $
#
# Makefile for snefru wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	snefru.o

.c.o:
	$(CC) $(CFLAGS) -c $<
	
clean:
	-rm -rf *.o .pure

snefru.o: ../../include/byteorder.h
