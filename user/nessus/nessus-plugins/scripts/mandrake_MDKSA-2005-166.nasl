#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:166
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19921);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2919", "CVE-2005-2920");
 
 name["english"] = "MDKSA-2005:166: clamav";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:166 (clamav).



A vulnerability was discovered in ClamAV versions prior to 0.87. A buffer
overflow could occure when processing malformed UPX-packed executables. As
well, it could be sent into an infinite loop when processing specially-crafted
FSG-packed executables.

ClamAV version 0.87 is provided with this update which isn't vulnerable to
these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:166
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the clamav package";
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
if ( rpm_check( reference:"clamav-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.87-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.87-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK10.1")
 || rpm_exists(rpm:"clamav-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2919", value:TRUE);
 set_kb_item(name:"CVE-2005-2920", value:TRUE);
}
