#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:070
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21207);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");
 
 name["english"] = "MDKSA-2006:070: sash";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:070 (sash).



Tavis Ormandy of the Gentoo Security Project discovered a vulnerability in zlib
where a certain data stream would cause zlib to corrupt a data structure,
resulting in the linked application to dump core (CVE-2005-2096). Markus
Oberhumber discovered additional ways that a specially-crafted compressed
stream could trigger an overflow. An attacker could create such a stream that
would cause a linked application to crash if opened by a user (CVE-2005-1849).
Both of these issues have previously been fixed in zlib, but sash links
statically against zlib and is thus also affected by these issues. New sash
packages are available that link against the updated zlib packages.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:070
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sash package";
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
if ( rpm_check( reference:"sash-3.7-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sash-3.7-3.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"sash-", release:"MDK10.2")
 || rpm_exists(rpm:"sash-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-1849", value:TRUE);
 set_kb_item(name:"CVE-2005-2096", value:TRUE);
}
