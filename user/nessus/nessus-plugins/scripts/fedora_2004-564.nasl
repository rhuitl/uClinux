#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16029);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0642", "CVE-2004-0644", "CVE-2004-0772", "CVE-2004-0971", "CVE-2004-1189");
 
 name["english"] = "Fedora Core 3 2004-564: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-564 (krb5).

Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

A heap based buffer overflow bug was found in the administration
library of Kerberos 1.3.5 and earlier. This overflow in the password
history handling code could allow an authenticated remote attacker to
execute commands on a realm's master Kerberos KDC. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2004-1189 to this issue.

Additionally a temporary file bug was found in the Kerberos
krb5-send-pr command. It is possible that an attacker could create a
specially crafted temporary file that could allow an arbitrary file
to be overwritten which the victim has write access to. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2004-0971 to this issue.



Solution : http://www.fedoranews.org/blog/index.php?p=219
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb5 package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"krb5-devel-1.3.6-2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.6-2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.6-2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.6-2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-debuginfo-1.3.6-2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"krb5-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-0642", value:TRUE);
 set_kb_item(name:"CVE-2004-0644", value:TRUE);
 set_kb_item(name:"CVE-2004-0772", value:TRUE);
 set_kb_item(name:"CVE-2004-0971", value:TRUE);
 set_kb_item(name:"CVE-2004-1189", value:TRUE);
}
