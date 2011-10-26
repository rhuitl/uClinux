#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:067
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21202);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1614", "CVE-2006-1615", "CVE-2006-1630");
 
 name["english"] = "MDKSA-2006:067: clamav";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:067 (clamav).



Damian Put discovered an integer overflow in the PE header parser in ClamAV
that could be exploited if the ArchiveMaxFileSize option was disabled
(CVE-2006-1614). Format strings in the logging code could possibly lead to the
execution of arbitrary code (CVE-2006-1615). David Luyer found that ClamAV
could be tricked into an invalid memory access in the cli_bitset_set()
function, which could lead to a Denial of Service (CVE-2006-1630). This update
provides ClamAV 0.88.1 which corrects this issue and also fixes some other
bugs.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:067
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
if ( rpm_check( reference:"clamav-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.88.1-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-db-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamav-milter-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"clamd-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libclamav1-devel-0.88.1-0.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"clamav-", release:"MDK10.2")
 || rpm_exists(rpm:"clamav-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1614", value:TRUE);
 set_kb_item(name:"CVE-2006-1615", value:TRUE);
 set_kb_item(name:"CVE-2006-1630", value:TRUE);
}
