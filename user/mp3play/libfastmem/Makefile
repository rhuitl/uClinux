#
# Makefile for fastmem library code.
#

LIBFASTMEM = libfastmem.a
OBJS = fastmem.o


all: $(LIBFASTMEM)

$(LIBFASTMEM): $(OBJS)
	$(AR) crv $(LIBFASTMEM) $(OBJS)

clean:
	rm -f $(LIBFASTMEM) $(OBJS) *.elf *.gdb

