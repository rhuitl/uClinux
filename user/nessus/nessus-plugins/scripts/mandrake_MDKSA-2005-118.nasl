#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:118
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19192);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1992");
 
 name["english"] = "MDKSA-2005:118: ruby";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:118 (ruby).



A vulnerability was discovered in ruby version 1.8 that could allow for the
execution of arbitrary commands on a server running the ruby xmlrpc server.

The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:118
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ruby package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ruby-1.8.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.1-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.2-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.2-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.2-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.2-6.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ruby-", release:"MDK10.1")
 || rpm_exists(rpm:"ruby-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1992", value:TRUE);
}
