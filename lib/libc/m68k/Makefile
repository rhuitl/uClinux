# Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a

ASRC=setjmp.S
AOBJ=setjmp.o

OBJ=$(AOBJ)

all: $(LIBC) ../crt0.o
	#@$(RM) $(OBJ)

../crt0.o: crt0.S
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBC): $(LIBC)($(OBJ))

$(LIBC)($(AOBJ)): $(ASRC)
	$(CC) $(CFLAGS) -DL_$* $< -c -o $*.o
	$(AR) $(ARFLAGS) $@ $*.o

clean:
	rm -f *.o libc.a
