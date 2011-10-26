#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:026
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20831);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-0758", "CVE-2005-0953");
 
 name["english"] = "MDKSA-2006:026: bzip2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:026 (bzip2).



A bug was found in the way that bzgrep processed file names. If a user could be
tricked into running bzgrep on a file with a special file name, it would be
possible to execute arbitrary code with the privileges of the user running
bzgrep. As well, the bzip2 package provided with Mandriva Linux 2006 did not
the patch applied to correct CVE-2005-0953 which was previously fixed by
MDKSA-2005:091; those packages are now properly patched. The updated packages
have been patched to correct these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:026
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bzip2 package";
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
if ( rpm_check( reference:"bzip2-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"bzip2-", release:"MDK10.1")
 || rpm_exists(rpm:"bzip2-", release:"MDK10.2")
 || rpm_exists(rpm:"bzip2-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0953", value:TRUE);
}
