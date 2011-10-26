#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:117
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15597);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0891");
 
 name["english"] = "MDKSA-2004:117: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:117 (gaim).



A vulnerability in the MSN protocol handler in the gaim instant messenger
application was discovered. When receiving unexpected sequences of MSNSLP
messages, it is possible that an attacker could trigger an internal buffer
overflow which could lead to a crash or even code execution as the user running
gaim.

The updated packages are patched to fix this problem. This problem does not
affect Mandrakelinux 10.0 installations.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:117
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-festival-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.82.1-2.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0891", value:TRUE);
}
