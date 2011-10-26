#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:046
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20964);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0300");
 
 name["english"] = "MDKSA-2006:046: tar";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:046 (tar).



Gnu tar versions 1.14 and above have a buffer overflow vulnerability and some
other issues including: - Carefully crafted invalid headers can cause buffer
overrun. - Invalid header fields go undiagnosed. - Some valid time strings are
ignored. The updated packages have been patched to address this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:046
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tar package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tar-1.14-1.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.15.1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"tar-1.15.1-5.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"tar-", release:"MDK10.1")
 || rpm_exists(rpm:"tar-", release:"MDK10.2")
 || rpm_exists(rpm:"tar-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-0300", value:TRUE);
}
