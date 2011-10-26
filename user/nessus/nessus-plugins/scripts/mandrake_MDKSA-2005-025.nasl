#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:025
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16291);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0133");
 
 name["english"] = "MDKSA-2005:025: clamav";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:025 (clamav).



Two problems were discovered in versions of clamav prior to 0.81. An attacker
could evade virus scanning by sending a base64-encoded imaege file in a URL.
Also, by sending a specially-crafted ZIP file, an attacker could cause a DoS
(Denial of Service) by crashing the clamd daemon.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:025
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
if ( rpm_check( reference:"clamav-0.81-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.81-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.81-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.81-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.81-0.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0133", value:TRUE);
}
