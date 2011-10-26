# Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
# This file is part of the Linux-8086 C library and is distributed
# under the GNU Library General Public License.

LIBC=../libc.a
CFLAGS += -I. -I$(MACHINE)

.S.s:
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -traditional -E -o $*.s $<
.S.o:
	$(CC) $(CFLAGS) -c -o $*.o $<

include $(MACHINE)/makefile.objs

all: $(LIBC)

$(LIBC): $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ)
	#@$(RM) $(OBJ)

transfer:
	-@rm -f ../include/stdio.h
	cp -p stdio.h ../include/.

clean:
	rm -f *.o libc.a
