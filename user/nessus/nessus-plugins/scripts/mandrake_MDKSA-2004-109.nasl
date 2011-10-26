#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:109
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15523);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");
 
 name["english"] = "MDKSA-2004:109: libtiff";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:109 (libtiff).


Several vulnerabilities have been discovered in the libtiff package:
Chris Evans discovered several problems in the RLE (run length encoding)
decoders that could lead to arbitrary code execution. (CVE-2004-0803) Matthias
Clasen discovered a division by zero through an integer overflow.
(CVE-2004-0804)
Dmitry V. Levin discovered several integer overflows that caused malloc issues
which can result to either plain crash or memory corruption. (CVE-2004-0886)


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:109
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libtiff package";
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
if ( rpm_check( reference:"libtiff-progs-3.5.7-11.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.5.7-11.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.5.7-11.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.5.7-11.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.5.7-11.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.5.7-11.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK10.0")
 || rpm_exists(rpm:"libtiff-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}
