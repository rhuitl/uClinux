# $Id: Makefile,v 1.19.2.4 2005/09/07 16:23:00 andrei Exp $
#
# acc module makefile
#
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
include ../../Makefile.radius

auto_gen=
NAME=acc.so
LIBS=

# uncomment the next line if you wish to enable SQL accounting
#DEFS+=-DSQL_ACC

# uncomment the next two lines if you wish to enable RADIUS accounting
#DEFS+=-DRAD_ACC
#include ../../Makefile.radius

# uncomment the next two lines if you wish to enable DIAMETER accounting
#DEFS+=-DDIAM_ACC

include ../../Makefile.modules
