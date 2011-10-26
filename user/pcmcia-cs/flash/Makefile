#
# flash/Makefile 1.18 2001/02/07 00:41:40 (David Hinds)
#

# Include site dependent options
include ../config.mk

# CFLAGS = -O -Wall -Wstrict-prototypes -pipe
# CC = $(UCC) $(UFLAGS)

SRCS  = ftl_format.c ftl_check.c
TOOLS = ftl_format ftl_check

all:	$(TOOLS)

ftl_format: ftl_format.o

ftl_check: ftl_check.o

clean:
	rm -f core core.* *.o *.s *.a *~ .depend .depfiles/*.d
	rm -f $(TOOLS)

install: $(TOOLS)
	@mkdir -p $(PREFIX)/sbin
	cp -f $(TOOLS) $(PREFIX)/sbin

include ../rules.mk
