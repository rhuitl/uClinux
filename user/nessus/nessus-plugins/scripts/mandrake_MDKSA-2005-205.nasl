#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:205
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20439);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3239", "CVE-2005-3303", "CVE-2005-3500", "CVE-2005-3501", "CVE-2005-3587");
 
 name["english"] = "MDKSA-2005:205: clamav";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:205 (clamav).



A number of vulnerabilities were discovered in ClamAV versions prior to 0.87.1:
The OLE2 unpacker in clamd allows remote attackers to cause a DoS (segfault)
via a DOC file with an invalid property tree (CVE-2005-3239) The FSG unpacker
allows remote attackers to cause 'memory corruption' and execute arbitrary code
via a crafted FSG 1.33 file (CVE-2005-3303) The tnef_attachment() function
allows remote attackers to cause a DoS (infinite loop and memory exhaustion)
via a crafted value in a CAB file that causes ClamAV to repeatedly scan the
same block (CVE-2005-3500) Remote attackers could cause a DoS (infinite loop)
via a crafted CAB file (CVE-2005-3501) An improper bounds check in petite.c
could allow attackers to perform unknown attacks via unknown vectors
(CVE-2005-3587) This update provides ClamAV 0.87.1 which corrects all of these
issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:205
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the clamav package";
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
if ( rpm_check( reference:"clamav-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.87.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.87.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.87.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK10.1")
 || rpm_exists(rpm:"clamav-", release:"MDK10.2")
 || rpm_exists(rpm:"clamav-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3239", value:TRUE);
 set_kb_item(name:"CVE-2005-3303", value:TRUE);
 set_kb_item(name:"CVE-2005-3500", value:TRUE);
 set_kb_item(name:"CVE-2005-3501", value:TRUE);
 set_kb_item(name:"CVE-2005-3587", value:TRUE);
}
