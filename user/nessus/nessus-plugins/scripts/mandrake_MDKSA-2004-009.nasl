#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14109);
 script_bugtraq_id(6116);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-1146");
 
 name["english"] = "MDKSA-2004:009: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:009 (glibc).


A read buffer overflow vulnerability exists in the resolver code in versions of
glibc up to and including 2.2.5. The vulnerability is triggered by DNS packets
larger than 1024 bytes, which can cause an application to crash.
The updated packages have a patch applied to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:009
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
if ( rpm_check( reference:"glibc-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-i18ndata-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-static-devel-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-utils-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ldconfig-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.5-16.4.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"glibc-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1146", value:TRUE);
}
