#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18327);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 
 name["english"] = "Fedora Core 2 2005-269: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-269 (krb5).

Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

Update Information:

Updated krb5 packages which fix two buffer overflow vulnerabilities
in the included Kerberos-aware telnet client are now available.

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each
other.

The krb5-workstation package includes a Kerberos-aware telnet client.
Two buffer overflow flaws were discovered in the way the telnet
client handles messages from a server. An attacker may be able to
execute arbitrary code on a victim's machine if the victim can be
tricked into connecting to a malicious telnet server. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the names CVE-2005-0468 and CVE-2005-0469 to these issues.


Solution : http://www.fedoranews.org/blog/index.php?p=539
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the krb5 package";
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
if ( rpm_check( reference:"krb5-devel-1.3.6-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.6-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.6-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.6-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-debuginfo-1.3.6-4", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"krb5-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0468", value:TRUE);
 set_kb_item(name:"CVE-2005-0469", value:TRUE);
}
