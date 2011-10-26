#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:053
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14152);
 script_bugtraq_id(10403, 8370);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0649", "CVE-2004-0402");
 
 name["english"] = "MDKSA-2004:053: xpcd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:053 (xpcd).


A vulnerability in xpcd-svga, part of xpcd, was discovered by Jaguar. xpcd-svga
uses svgalib to display graphics on the console and it would copy user-supplied
data of an arbitrary length into a fixed-size buffer in the pcd_open function.
As well, Steve Kemp previously discovered a buffer overflow in xpcd-svga that
could be triggered by a long HOME environment variable, which could be exploited
by a local attacker to obtain root privileges.
The updated packages resolve these vulnerabilities.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:053
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xpcd package";
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
if ( rpm_check( reference:"xpcd-2.08-20.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpcd-gimp-2.08-20.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpcd-2.08-20.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xpcd-gimp-2.08-20.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xpcd-", release:"MDK10.0")
 || rpm_exists(rpm:"xpcd-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0649", value:TRUE);
 set_kb_item(name:"CVE-2004-0402", value:TRUE);
}
