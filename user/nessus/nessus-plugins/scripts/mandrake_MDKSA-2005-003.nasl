#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:003
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16116);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1138");
 
 name["english"] = "MDKSA-2005:003: vim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:003 (vim).



Several 'modeline'-related vulnerabilities were discovered in Vim by Ciaran
McCreesh. The updated packages have been patched with Bram Moolenaar's vim
6.3.045 patch which fixes the reported vulnerabilities and adds more
conservative 'modeline' rights.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:003
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the vim package";
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
if ( rpm_check( reference:"vim-X11-6.2-14.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.2-14.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.2-14.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.2-14.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.3-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.3-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.3-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.3-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-X11-6.2-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-common-6.2-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-enhanced-6.2-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"vim-minimal-6.2-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"vim-", release:"MDK10.0")
 || rpm_exists(rpm:"vim-", release:"MDK10.1")
 || rpm_exists(rpm:"vim-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1138", value:TRUE);
}
