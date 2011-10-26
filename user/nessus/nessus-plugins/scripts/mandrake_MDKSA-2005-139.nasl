#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:139
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19896);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
 
 name["english"] = "MDKSA-2005:139: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:139 (gaim).



Yet more vulnerabilities have been discovered in the gaim IM client. Invalid
characters in a sent file can cause Gaim to crash on some systems
(CVE-2005-2102); a remote AIM or ICQ user can cause a buffer overflow in Gaim
by setting an away message containing many AIM substitution strings
(CVE-2005-2103); a memory alignment bug in the library used by Gaim to access
the Gadu-Gadu network can result in a buffer overflow on non-x86 architecture
systems (CVE-2005-2370).

These problems have been corrected in gaim 1.5.0 which is provided with this
update.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:139
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
if ( rpm_check( reference:"gaim-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-silc-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.1")
 || rpm_exists(rpm:"gaim-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}
