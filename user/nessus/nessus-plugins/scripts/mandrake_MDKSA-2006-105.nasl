#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2006:105
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21720);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-2449");
 
 name["english"] = "MDKSA-2006:105: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2006:105 (kdebase).



A problem with how kdm manages the ~/.dmrc file was discovered by

Ludwig Nussel. By using a symlink attack, a local user could get kdm

to read arbitrary files on the system, including privileged system

files and those belonging to other users.



The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:105
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase package";
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
if ( rpm_check( reference:"kdebase-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-common-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kate-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kcontrol-data-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kcontrol-nsplugins-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdeprintfax-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kdm-config-file-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-kmenuedit-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-konsole-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-nsplugins-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-progs-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-devel-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-kate-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-kate-devel-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-kmenuedit-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdebase4-konsole-3.4.2-55.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdebase-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-2449", value:TRUE);
}
