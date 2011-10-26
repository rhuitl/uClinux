#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:201
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20127);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2959");
 
 name["english"] = "MDKSA-2005:201: sudo";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:201 (sudo).



Tavis Ormandy discovered that sudo does not perform sufficient environment
cleaning; in particular the SHELLOPTS and PS4 variables are still passed to the
program running as an alternate user which can result in the execution of
arbitrary commands as the alternate user when a bash script is executed. The
updated packages have been patched to correct this problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:201
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sudo package";
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
if ( rpm_check( reference:"sudo-1.6.8p1-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p8-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sudo-", release:"MDK10.1")
 || rpm_exists(rpm:"sudo-", release:"MDK10.2")
 || rpm_exists(rpm:"sudo-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2959", value:TRUE);
}
