#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:073
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18103);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0753");
 
 name["english"] = "MDKSA-2005:073: cvs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:073 (cvs).



A buffer overflow and memory access problem in CVS have been discovered by the
CVS maintainer. The updated packages have been patched to correct the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:073
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the cvs package";
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
if ( rpm_check( reference:"cvs-1.11.17-1.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.17-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.19-1.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK10.1")
 || rpm_exists(rpm:"cvs-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0753", value:TRUE);
}
