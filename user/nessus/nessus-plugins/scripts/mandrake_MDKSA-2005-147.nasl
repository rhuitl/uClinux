#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:147
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19903);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2499");
 
 name["english"] = "MDKSA-2005:147: slocate";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:147 (slocate).



A bug was discovered in the way that slocate processes very long paths. A local
user could create a carefully crafted directory structure that would prevent
updatedb from completing its filesystem scan, resulting in an incomplete
database.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:147
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the slocate package";
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
if ( rpm_check( reference:"slocate-2.7-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"slocate-2.7-4.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"slocate-", release:"MDK10.0")
 || rpm_exists(rpm:"slocate-", release:"MDK10.1")
 || rpm_exists(rpm:"slocate-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2499", value:TRUE);
}
