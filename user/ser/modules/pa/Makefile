# $Id: Makefile,v 1.4.2.3 2005/06/06 16:27:32 andrei Exp $
#
# Presence Agent
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=pa.so
LIBS=

DEFS+=-I/usr/include/libxml2 -I$(LOCALBASE)/include/libxml2 \
	-I$(LOCALBASE)/include
LIBS+=-L/usr/include/lib  -L$(LOCALBASE)/lib -lxml2

include ../../Makefile.modules
