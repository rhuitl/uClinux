#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20230);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
 
 name["english"] = "Fedora Core 3 2005-1086: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1086 (gdk-pixbuf).

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment. The GdkPixBuf library provides image
loading facilities, the rendering of a GdkPixBuf into various formats
(drawables or GdkRGB buffers), and a cache interface.

Update Information:

The gdk-pixbuf package contains an image loading library
used with the GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes XPM images.
An attacker could create a carefully crafted XPM file in
such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code when the file was
opened by a victim. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-3186 to this issue.

Ludwig Nussel discovered an integer overflow bug in the way
gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause
an application linked with gdk-pixbuf to execute arbitrary
code or crash when the file was opened by a victim. The
Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2976 to this issue.

Ludwig Nussel also discovered an infinite-loop denial of
service bug in the way gdk-pixbuf processes XPM images. An
attacker could create a carefully crafted XPM file in such a
way that it could cause an application linked with
gdk-pixbuf to stop responding when the file was opened by a
victim. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2975 to this issue.

Users of gdk-pixbuf are advised to upgrade to these updated
packages, which contain backported patches and are not
vulnerable to these issues.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gdk-pixbuf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-16.fc3.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gdk-pixbuf-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2975", value:TRUE);
 set_kb_item(name:"CVE-2005-2976", value:TRUE);
 set_kb_item(name:"CVE-2005-3186", value:TRUE);
}
