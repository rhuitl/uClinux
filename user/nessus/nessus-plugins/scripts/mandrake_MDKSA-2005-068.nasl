#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:068
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18003);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0891");
 
 name["english"] = "MDKSA-2005:068: gtk+2.0";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:068 (gtk+2.0).



A bug was discovered in the way that gtk+2.0 processes BMP images which could
allow for a specially crafted BMP to cause a Denial of Service attack on
applications linked against gtk+2.0.

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:068
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtk+2.0 package";
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
if ( rpm_check( reference:"gtk+2.0-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-linuxfb-2.0_0-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-linuxfb-2.0_0-devel-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.2.4-10.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.4.9-9.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gtk+2.0-", release:"MDK10.0")
 || rpm_exists(rpm:"gtk+2.0-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0891", value:TRUE);
}
