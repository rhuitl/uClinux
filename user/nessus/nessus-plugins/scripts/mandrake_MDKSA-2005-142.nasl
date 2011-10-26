#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:142
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19899);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2452");
 
 name["english"] = "MDKSA-2005:142: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:142 (libtiff).



Wouter Hanegraaff discovered that the TIFF library did not sufficiently
validate the 'YCbCr subsampling' value in TIFF image headers. Decoding a
malicious image with a zero value resulted in an arithmetic exception, which
can cause a program that uses the TIFF library to crash.

The updated packages are patched to protect against this vulnerability.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:142
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-progs-3.5.7-11.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.5.7-11.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.5.7-11.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.5.7-11.7.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-4.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.6.1-4.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-4.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-4.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-11.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.6.1-11.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-11.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-11.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK10.0")
 || rpm_exists(rpm:"libtiff-", release:"MDK10.1")
 || rpm_exists(rpm:"libtiff-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2452", value:TRUE);
}
