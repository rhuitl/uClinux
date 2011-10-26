#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:007
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16158);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");
 
 name["english"] = "MDKSA-2005:007: imlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:007 (imlib).



Pavel Kankovsky discovered several heap overflow flaw in the imlib image
handler. An attacker could create a carefully crafted image file in such a way
that it could cause an application linked with imlib to execute arbitrary code
when the file was opened by a user (CVE-2004-1025).

As well, Pavel also discovered several integer overflows in imlib. These could
allow an attacker, creating a carefully crafted image file, to cause an
application linked with imlib to execute arbitrary code or crash
(CVE-2004-1026).

The updated packages have been patched to prevent these problems.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:007
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib package";
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
if ( rpm_check( reference:"imlib-1.9.14-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.14-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.14-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.14-8.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.0.6-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.0.6-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.0.6-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.0.6-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.14-10.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.14-10.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.14-10.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.14-10.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.1.0-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.1.0-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.1.0-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.1.0-4.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.14-8.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.14-8.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.14-8.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.14-8.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.0.6-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.0.6-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.0.6-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.0.6-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"imlib-", release:"MDK10.0")
 || rpm_exists(rpm:"imlib-", release:"MDK10.1")
 || rpm_exists(rpm:"imlib-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1025", value:TRUE);
 set_kb_item(name:"CVE-2004-1026", value:TRUE);
}
