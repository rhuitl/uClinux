#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:003
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14103);
 script_bugtraq_id(9419);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0988");
 
 name["english"] = "MDKSA-2004:003: kdepim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:003 (kdepim).


A vulnerability was discovered in all versions of kdepim as distributed with KDE
versions 3.1.0 through 3.1.4. This vulnerability allows for a carefully crafted
.VCF file to potentially enable a local attacker to compromise the privacy of a
victim's data or execute arbitrary commands with the victim's privileges. This
can also be used by remote attackers if the victim enables previews for remote
files; however this is disabled by default.
The provided packages contain a patch from the KDE team to correct this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:003
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdepim package";
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
if ( rpm_check( reference:"kdepim-3.1-17.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-devel-3.1-17.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-common-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-kaddressbook-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-karm-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-knotes-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-korganizer-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdepim-kpilot-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdepim2-common-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdepim2-kpilot-3.1.3-22.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdepim-", release:"MDK9.1")
 || rpm_exists(rpm:"kdepim-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0988", value:TRUE);
}
