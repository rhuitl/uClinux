# $Id: Makefile,v 1.5.2.3 2005/09/07 19:21:03 andrei Exp $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=postgres.so

# libpq-fe.h locations
DEFS +=-I$(LOCALBASE)/include -I$(LOCALBASE)/pgsql/include  \
	-I$(LOCALBASE)/include/postgresql \
	-I/usr/include/postgresql -I/usr/include/postgresql/8.0
LIBS=-L$(LOCALBASE)/lib -L$(LOCALBASE)/pgsql/lib -L$(LOCALBASE)/lib/pgsql -lpq

include ../../Makefile.modules
