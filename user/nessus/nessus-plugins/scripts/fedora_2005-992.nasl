#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20167);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-992: openldap";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-992 (openldap).

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools. LDAP is a set of
protocols for accessing directory services (usually phone book style
information, but other information is possible) over the Internet,
similar to the way DNS (Domain Name System) information is propagated
over the Internet. The openldap package contains configuration files,
libraries, and documentation for OpenLDAP.

Update Information:

This is an experimental upgrade of OpenLDAP to 2.2.29 for
FC4.  Before I push it to final, I need some confirmation
that upgrading to it will not break existing
configurations.  If I don't hear any objections, I should
push it to final in a week or so.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openldap package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openldap-2.2.29-1.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-devel-2.2.29-1.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-servers-2.2.29-1.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap-clients-2.2.29-1.FC4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
