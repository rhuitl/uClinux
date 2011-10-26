#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:016-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13924);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2002:016-1: squid";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:016-1 (squid).


Three security issues were found in the 2.x versions of the Squid proxy server
up to and including 2.4.STABLE3. The first is a memory leak in the optional SNMP
interface to Squid which could allow a malicious user who can send packets to
the Squid SNMP port to possibly perform a Denial of Service attack on ther
server if the SNMP interface is enabled. The next is a buffer overflow in the
implementation of ftp:// URLs where allowed users could possibly perform a DoS
on the server, and may be able to trigger remote execution of code (which the
authors have not yet confirmed). The final issue is with the HTCP interface
which cannot be properly disabled from squid.conf; HTCP is enabled by default on
Mandrake Linux systems.
Update:
The squid updates for all versions other than Mandrake Linux were incorrectly
built with LDAP authentication which introduced a dependency on OpenLDAP. These
new packages do not use LDAP authentication. The Single Network Firewall 7.2
package previously released did not use LDAP authentication, however rebuilding
the source RPM package required LDAP to be installed. Single Network Firewall
7.2 users do not need to upgrade to these packages to have a properly function
squid.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:016-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the squid package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"squid-2.4.STABLE4-1.5mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE4-1.5mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"squid-2.4.STABLE4-1.6mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
