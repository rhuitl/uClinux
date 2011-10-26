#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13710);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0017");
 script_bugtraq_id(10448);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0523");
 
 name["english"] = "Fedora Core 1 2004-149: krb5";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-149 (krb5).

Kerberos V5 is a trusted-third-party network authentication system,
which can improve your network's security by eliminating the insecure
practice of cleartext passwords.

Update Information:

Bugs have been fixed in the krb5_aname_to_localname library function.
Specifically, buffer overflows were possible for all Kerberos
versions up to and including 1.3.3. The krb5_aname_to_localname
function translates a Kerberos principal name to a local account
name, typically a UNIX username.  This function is frequently used
when performing authorization checks.

If configured with mappings from particular Kerberos principals to
particular UNIX user names, certain functions called by
krb5_aname_to_localname will not properly check the lengths of
buffers used to store portions of the principal name. If configured
to map principals to user names using rules, krb5_aname_to_localname
would consistently write one byte past the end of a buffer allocated
from the heap. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0523 to this issue.

Only configurations which enable the explicit mapping or rules-based
mapping functionality of krb5_aname_to_localname() are vulnerable.
These configurations are not the default.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-149.shtml
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
if ( rpm_check( reference:"krb5-devel-1.3.3-6", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-libs-1.3.3-6", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-server-1.3.3-6", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-workstation-1.3.3-6", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"krb5-debuginfo-1.3.3-6", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"krb5-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0523", value:TRUE);
}
