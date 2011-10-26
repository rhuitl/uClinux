# Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a

CFLAGS+=-DFLOAT=1
OBJ= gcvt.o fpscan.o fabs.o

all: $(LIBC) $(OBJ)
	#@$(RM) $(OBJ)

$(LIBC): $(LIBC)($(OBJ))

transfer:
	-@rm -f ../include/stdio.h
	cp -p stdio.h ../include/.

clean:
	rm -f *.o

