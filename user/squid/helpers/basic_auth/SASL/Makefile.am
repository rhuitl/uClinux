#
#  Makefile for the Squid SASL authentication helper
#
#  $Id: Makefile.am,v 1.1.2.4 2004/06/08 11:35:22 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

INCLUDES	= -I$(top_srcdir)/include

libexec_PROGRAMS	= sasl_auth
LDADD			= -L$(top_builddir)/lib -lmiscutil $(LIBSASL) $(XTRA_LIBS)
EXTRA_DIST		= squid_sasl_auth squid_sasl_auth.conf
