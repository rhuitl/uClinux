# $Id: Makefile,v 1.3 1993/11/22 06:38:14 genek Exp $
#
# Makefile for MD2 wrapper
#
# Gene Kim
# Purdue University
# October 18, 1992
#

all:	md2wrapper.o md2.o

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -rf *.o .pure

md2.o: ../../include/byteorder.h
md2wrapper.o: ../../include/byteorder.h
