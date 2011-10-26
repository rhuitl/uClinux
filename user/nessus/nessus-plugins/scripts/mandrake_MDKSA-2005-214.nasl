#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:214
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20446);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788", "CVE-2005-0891", "CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 
 name["english"] = "MDKSA-2005:214: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:214 (gdk-pixbuf).



A heap overflow vulnerability in the GTK+ gdk-pixbuf XPM image rendering
library could allow for arbitrary code execution. This allows an attacker to
provide a carefully crafted XPM image which could possibly allow for arbitrary
code execution in the context of the user viewing the image. (CVE-2005-3186)
Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
processes XPM images. An attacker could create a carefully crafted XPM file in
such a way that it could cause an application linked with gdk-pixbuf to execute
arbitrary code or crash when the file was opened by a victim. (CVE-2005-2976)
Ludwig Nussel also discovered an infinite-loop denial of service bug in the way
gdk-pixbuf processes XPM images. An attacker could create a carefully crafted
XPM file in such a way that it could cause an application linked with
gdk-pixbuf to stop responding when the file was opened by a victim.
(CVE-2005-2975) The gtk+2.0 library also contains the same gdk-pixbuf code with
the same vulnerability. The Corporate Server 2.1 packages have additional
patches to address CVE-2004-0782,0783,0788 (additional XPM/ICO image issues),
CVE-2004-0753 (BMP image issues) and CVE-2005-0891 (additional BMP issues).
These were overlooked on this platform with earlier updates. The updated
packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:214
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk-pixbuf package";
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
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-8.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.6.4-2.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-devel-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-8.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.8.3-4.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdk-pixbuf-", release:"MDK10.2")
 || rpm_exists(rpm:"gdk-pixbuf-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
