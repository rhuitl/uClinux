#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19639);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0891");
 
 name["english"] = "Fedora Core 3 2005-266: gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-266 (gdk-pixbuf).

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment. The GdkPixBuf library provides image
loading facilities, the rendering of a GdkPixBuf into various formats
(drawables or GdkRGB buffers), and a cache interface.

Update Information:
David Costanzo found a bug in the way gdk-pixbuf processes BMP images.
It is possible that a specially crafted BMP image could cause a denial
of service attack in applications linked against gdk-pixbuf.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0891 to this issue.



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
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-16.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gdk-pixbuf-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0891", value:TRUE);
}
