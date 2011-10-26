#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:086
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14068);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0688");
 
 name["english"] = "MDKSA-2003:086: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:086 (sendmail).


A vulnerability was discovered in all 8.12.x versions of sendmail up to and
including 8.12.8. Due to wrong initialization of RESOURCE_RECORD_T structures,
if sendmail receives a bad DNS reply it will call free() on random addresses
which usually causes sendmail to crash.
These updated packages are patched to fix the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:086
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail package";
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
if ( rpm_check( reference:"sendmail-8.12.1-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.1-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.1-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.1-4.4mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.6-3.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.6-3.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.6-3.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.6-3.4mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"MDK8.2")
 || rpm_exists(rpm:"sendmail-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0688", value:TRUE);
}
