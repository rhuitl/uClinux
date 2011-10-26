#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:095-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14751);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
 
 name["english"] = "MDKSA-2004:095-1: gdk-pixbuf/gtk+2";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:095-1 (gdk-pixbuf/gtk+2).


A vulnerability was found in the gdk-pixbug bmp loader where a bad BMP image
could send the bmp loader into an infinite loop (CVE-2004-0753).
Chris Evans found a heap-based overflow and a stack-based overflow in the xpm
loader of gdk-pixbuf (CVE-2004-0782 and CVE-2004-0783).
Chris Evans also discovered an integer overflow in the ico loader of gdk-pixbuf
(CVE-2004-0788).
All four problems have been corrected in these updated packages.
Update:
The previous package had an incorrect patch applied that would cause some
problems with other programs. The updated packages have the correct patch
applied.
As well, patched gtk+2 packages, which also contain gdk-pixbuf, are now
provided.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:095-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk-pixbuf/gtk+2 package";
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
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.2.4-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.2.4-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.2.4-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.2.4-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.2.4-10.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-loaders-0.22.0-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf-xlib2-0.22.0-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-0.22.0-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk-pixbuf2-devel-0.22.0-2.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk+2.0-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgdk_pixbuf2.0_0-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-linuxfb-2.0_0-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+-x11-2.0_0-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgtk+2.0_0-devel-2.2.4-2.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gdk-pixbuf-", release:"MDK10.0")
 || rpm_exists(rpm:"gdk-pixbuf-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
}
