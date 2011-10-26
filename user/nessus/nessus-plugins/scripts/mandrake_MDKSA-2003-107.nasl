#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:107
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14089);
 script_bugtraq_id(8477);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0689");
 
 name["english"] = "MDKSA-2003:107: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:107 (glibc).


A bug was discovered in the getgrouplist function in glibc that can cause a
buffer overflow if the size of the group list is too small to hold all the
user's groups. This overflow can cause segementation faults in various user
applications, some of which may lead to additional security problems. The
problem can only be triggered if the user is in a larger number of groups than
expected by an application.
The provided packages are patched to address this issue.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:107
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc package";
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
if ( rpm_check( reference:"glibc-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-i18ndata-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-static-devel-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"timezone-2.2.5-16.3.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-debug-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-i18ndata-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-static-devel-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"timezone-2.3.1-10.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"MDK9.0")
 || rpm_exists(rpm:"glibc-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0689", value:TRUE);
}
