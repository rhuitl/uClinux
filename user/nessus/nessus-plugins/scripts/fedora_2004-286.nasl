#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14741);
 script_version ("$Revision: 1.3 $");
 script_bugtraq_id(11195);
 script_cve_id("CVE-2004-0691", "CVE-2004-0753", "CVE-2004-0783", "CVE-2004-0788");
 
 name["english"] = "Fedora Core 1 2004-286: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-286 (gdk-pixbuf).

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment. The GdkPixBuf library provides image
loading facilities, the rendering of a GdkPixBuf into various formats
(drawables or GdkRGB buffers), and a cache interface.

Update Information:

During testing of a previously fixed flaw in Qt (CVE-2004-0691), a flaw
was discovered in the BMP image processor of gdk-pixbuf. An attacker could
create a carefully crafted BMP file which would cause an application
to enter an infinite loop and not respond to user input when the file
was opened by a victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0753 to this issue.

During a security audit, Chris Evans discovered a stack and a heap
overflow in the XPM image decoder. An attacker could create a carefully crafted
XPM file which could cause an application linked with gtk2 to crash or
possibly execute arbitrary code when the file was opened by a victim.
(CVE-2004-0782, CVE-2004-0783)

Chris Evans also discovered an integer overflow in the ICO image
decoder. An attacker could create a carefully crafted ICO file which could cause
an application linked with gtk2 to crash when the file is opened by a
victim. (CVE-2004-0788)



Solution : http://www.fedoranews.org/updates/FEDORA-2004-286.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk-pixbuf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-11.2.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-11.2.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-gnome-0.22.0-11.2.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-debuginfo-0.22.0-11.2.2", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gdk-pixbuf-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0691", value:TRUE);
 set_kb_item(name:"CVE-2004-0753", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
}
