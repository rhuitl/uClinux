#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:091
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14680);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(11075);
 script_cve_id("CVE-2004-0806");
 
 name["english"] = "MDKSA-2004:091: cdrecord";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:091 (cdrecord).


Max Vozeler found that the cdrecord program, which is suid root, fails to drop
euid=0 when it exec()s a program specified by the user through the $RSH
environment variable. This can be abused by a local attacker to obtain root
privileges.
The updated packages are patched to fix the vulnerability.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:091
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cdrecord package";
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
if ( rpm_check( reference:"cdrecord-2.01-0.a28.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01-0.a28.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01-0.a28.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-2.01-0.a18.2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cdrecord-devel-2.01-0.a18.2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mkisofs-2.01-0.a18.2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cdrecord-", release:"MDK10.0")
 || rpm_exists(rpm:"cdrecord-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0806", value:TRUE);
}
