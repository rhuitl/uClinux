# Makefile for cgihtml.a
# Based on original Makefile of Eugene Eric Kim <eekim@eekim.com>
# 
# Adapted to the uClinux dist by
# Heiko Degenhardt <linux@sentec-elektronik.de>
# Version:      01.00
# Date:         20030325
# 
# ATTENTION!
# There are security bugs in that version of cgihtml!
# Don't use this version on a remote accessible server!
# Search for "cgihtml" at http://www.securityfocus.com/search!
# 
# CHANGES
#
# 20030325	- adapted to the uClinux-dist
# 				  (hede)


# macros and variables
RANLIB = $(CROSS)ranlib

# Set UPLOADDIR to your (witeable) directory for uploads:
CFLAGS += -DUNIX -DUPLOADDIR='"/usr/tmp"'

OBJS = string-lib.o cgi-llist.o cgi-lib.o html-lib.o
LIB = cgihtml.a

# targets
$(LIB): $(OBJS)
	$(CROSS)ar cr $@ $(OBJS)
	$(RANLIB) $@

examples: $(LIB)
	cd examples; make all

all: examples

install: all
	cp -f *.h $(LIB) $(INSTALLDIR)
	cd examples; make install

clean:
	-rm -f *.o $(LIB)

clobber:
	-rm -f *.o $(LIB)
	cd examples; make clean

