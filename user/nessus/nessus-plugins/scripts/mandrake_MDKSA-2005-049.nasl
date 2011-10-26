#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:049
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17278);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0208", "CVE-2005-0472", "CVE-2005-0473");
 
 name["english"] = "MDKSA-2005:049: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:049 (gaim).



Gaim versions prior to version 1.1.4 suffer from a few security issues such as
the HTML parses not sufficiently validating its input. This allowed a remote
attacker to crash the Gaim client be sending certain malformed HTML messages
(CVE-2005-0208 and CVE-2005-0473).

As well, insufficient input validation was also discovered in the 'Oscar'
protocol handler, used for ICQ and AIM. By sending specially crafted packets,
remote users could trigger an inifinite loop in Gaim causing it to become
unresponsive and hang (CVE-2005-0472).

Gaim 1.1.4 is provided and fixes these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:049
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.1.4-2.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.1.4-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.0")
 || rpm_exists(rpm:"gaim-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0208", value:TRUE);
 set_kb_item(name:"CVE-2005-0472", value:TRUE);
 set_kb_item(name:"CVE-2005-0473", value:TRUE);
}
