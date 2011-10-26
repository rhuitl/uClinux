#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:046
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17215);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0503");
 
 name["english"] = "MDKSA-2005:046: uim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:046 (uim).



Takumi ASAKI discovered that uim always trusts environment variables which can
allow a local attacker to obtain elevated privileges when libuim is linked
against an suid/sgid application. This problem is only exploitable in 'immodule
for Qt' enabled Qt applications.

The updated packages are patched to fix the problem.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:046
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the uim package";
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
if ( rpm_check( reference:"libuim0-0.4.5.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libuim0-devel-0.4.5.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"uim-0.4.5.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"uim-applet-0.4.5.1-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"uim-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0503", value:TRUE);
}
