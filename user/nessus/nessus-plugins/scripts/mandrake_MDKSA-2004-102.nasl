#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:102
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14796);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0827");
 
 name["english"] = "MDKSA-2004:102: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:102 (ImageMagick).


Several buffer overflow vulnerabilities in ImageMagick were discovered by Marcus
Meissner from SUSE. These vulnerabilities would allow an attacker to create a
malicious image or video file in AVI, BMP, or DIB formats which could crash the
reading process. It may be possible to create malicious images that could also
allow for the execution of arbitray code with the privileges of the invoking
user or process.
The updated packages provided are patched to correct these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:102
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ImageMagick-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-5.5.7.15-6.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-5.5.7.10-7.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK10.0")
 || rpm_exists(rpm:"ImageMagick-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0827", value:TRUE);
}
