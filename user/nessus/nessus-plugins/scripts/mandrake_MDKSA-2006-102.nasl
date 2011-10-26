#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:102
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21717);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2193");
 
 name["english"] = "MDKSA-2006:102: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:102 (libtiff).



A buffer overflow in the t2p_write_pdf_string function in tiff2pdf in

libtiff 3.8.2 and earlier allows attackers to cause a denial of service

(crash) and possibly execute arbitrary code via a TIFF file with a

DocumentName tag that contains UTF-8 characters, which triggers the

overflow when a character is sign extended to an integer that produces

more digits than expected in a sprintf call.



Corporate Server 3 and Corporate Desktop 3 are not affected by this

vulnerability as tiff2pdf was not part of the libtiff version shipped

in those products.



The updated packages have been patched to correct this issue.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:102
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff3-3.6.1-11.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-11.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-11.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-11.5.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.6.1-12.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.6.1-12.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.6.1-12.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.6.1-12.4.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK10.2")
 || rpm_exists(rpm:"libtiff-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2193", value:TRUE);
}
