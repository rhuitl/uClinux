# $Id: Makefile,v 1.3 1993/11/22 06:38:10 genek Exp $
#
# Makefile for crc32 wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	crc.o

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -rf *.o .pure

crc.o: ../../include/byteorder.h
