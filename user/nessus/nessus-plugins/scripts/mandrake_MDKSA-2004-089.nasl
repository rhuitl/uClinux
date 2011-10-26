#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:089
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14678);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0802", "CVE-2004-0817");
 
 name["english"] = "MDKSA-2004:089: imlib2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:089 (imlib2).


Marcus Meissner discovered that the imlib and imlib2 libraries are also affected
with a similar BMP-related vulnerability as the recent QT updates. The updated
imlib and imlib2 packages are patched to protect against this problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:089
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib2 package";
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
if ( rpm_check( reference:"imlib-1.9.14-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.14-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.14-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.14-8.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.0.6-4.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.14-8.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.14-8.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-1.9.14-8.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib1-devel-1.9.14-8.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.0.6-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.0.6-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.0.6-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.0.6-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"imlib2-", release:"MDK10.0")
 || rpm_exists(rpm:"imlib2-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0802", value:TRUE);
 set_kb_item(name:"CVE-2004-0817", value:TRUE);
}
