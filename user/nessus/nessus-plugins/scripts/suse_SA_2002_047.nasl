#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2002:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13768);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "SUSE-SA:2002:047: OpenLDAP2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2002:047 (OpenLDAP2).


OpenLDAP is the Open Source implementation of the Lightweight Directory
Access Protocol (LDAP) and is used in network environments for distributing
certain information such as X.509 certificates or login information.

The SUSE Security Team reviewed critical parts of that package and found
several buffer overflows and other bugs remote attackers could exploit
to gain access on systems running vulnerable LDAP servers.
In addition to these bugs, various local exploitable bugs within the
OpenLDAP2 libraries (openldap2-devel package) have been fixed.

Since there is no workaround possible except shutting down the LDAP server,
we strongly recommend an update.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2002_047_openldap2.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the OpenLDAP2 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openldap2-2.0.11-66", release:"SUSE7.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-2.0.11-67", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.0.11-67", release:"SUSE7.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-2.0.12-44", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.0.12-44", release:"SUSE7.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-2.0.23-143", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openldap2-devel-2.0.23-143", release:"SUSE8.0") )
{
 security_hole(0);
 exit(0);
}
