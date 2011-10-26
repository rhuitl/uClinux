# $Id: Makefile,v 1.4 1993/12/13 04:02:30 genek Exp $
#
# Makefile for crc32 wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	crc32.o

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -f *.o .pure

crc32.o: ../../include/byteorder.h
