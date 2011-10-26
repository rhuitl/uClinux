#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:124
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19885);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");
 
 name["english"] = "MDKSA-2005:124: zlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:124 (zlib).



A previous zlib update (MDKSA-2005:112; CVE-2005-2096) fixed an overflow flaw
in the zlib program. While that update did indeed fix the reported overflow
issue, Markus Oberhumber discovered additional ways that a specially-crafted
compressed stream could trigger an overflow. An attacker could create such a
stream that would cause a linked application to crash if opened by a user.

The updated packages are provided to protect against this flaw. The Corporate
Server 2.1 product is not affected by this vulnerability.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:124
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the zlib package";
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
if ( rpm_check( reference:"zlib1-1.2.1-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1-2.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.1.1-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.1.1-3.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.2.2.2-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.2.2.2-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK10.0")
 || rpm_exists(rpm:"zlib-", release:"MDK10.1")
 || rpm_exists(rpm:"zlib-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
