#
#  Makefile for the Squid LDAP authentication helper
#
#  $Id: Makefile.am,v 1.1.2.4 2005/03/19 00:54:10 hno Exp $
#
#  Uncomment and customize the following to suit your needs:
#

libexec_PROGRAMS 	= squid_ldap_group
man_MANS 		= squid_ldap_group.8
EXTRA_DIST		= squid_ldap_group.8
squid_ldap_group_SOURCES	= squid_ldap_group.c

LDADD = -lldap $(LIB_LBER) $(XTRA_LIBS)
