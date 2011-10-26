
####################################
# This is a makefile for mawk,
# an implementation of AWK (1988).
####################################
#
#

CC = cc
CFLAGS = -O  -DMAWK -I..

O=rexp.o rexp0.o rexp1.o rexp2.o rexp3.o 
DB=rexpdb.o

all : $(O)
	@cat </dev/null > .done

debug : $(O) $(DB)
	@cat </dev/null > .done

$(O) : rexp.h

clean :
	rm -f *.o .done
