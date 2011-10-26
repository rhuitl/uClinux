#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14593);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_bugtraq_id(11078, 11079);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0642", "CVE-2004-0643", "CVE-2004-0644", "CVE-2004-0772");
 
 name["english"] = "Fedora Core 2 2004-277: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-277 (krb5).

Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

Update Information:

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each
other.

Several double-free bugs were found in the Kerberos 5 KDC and
libraries. A remote attacker could potentially exploit these flaws to
execute arbitrary code. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the names CVE-2004-0642 and
CVE-2004-0643 to these issues.

A double-free bug was also found in the krb524 server
(CVE-2004-0772), however this issue does not affect Fedora Core.

An infinite loop bug was found in the Kerberos 5 ASN.1 decoder
library. A remote attacker may be able to trigger this flaw and cause
a denial of service. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0644 to this issue.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-277.shtml
Risk Factor : High";



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
if ( rpm_check( reference:"krb5-devel-1.3.4-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.4-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.4-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.4-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-debuginfo-1.3.4-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"krb5-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0642", value:TRUE);
 set_kb_item(name:"CVE-2004-0643", value:TRUE);
 set_kb_item(name:"CVE-2004-0644", value:TRUE);
 set_kb_item(name:"CVE-2004-0772", value:TRUE);
}
