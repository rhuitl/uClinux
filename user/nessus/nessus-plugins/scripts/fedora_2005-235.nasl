#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19628);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0005", "CVE-2005-0397");
 
 name["english"] = "Fedora Core 3 2005-235: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-235 (ImageMagick).

ImageMagick(TM) is an image display and manipulation tool for the X
Window System. ImageMagick can read and write JPEG, TIFF, PNM, GIF,
and Photo CD image formats. It can resize, rotate, sharpen, color
reduce, or add special effects to an image, and when finished you can
either save the completed work in the original format or a different
one. ImageMagick also includes command line programs for creating
animated or transparent .gifs, creating composite images, creating
thumbnail images, and more.

ImageMagick is one of your choices if you need a program to manipulate
and dis play images. If you want to develop your own applications
which use ImageMagick code or APIs, you need to install
ImageMagick-devel as well.

Update Information:

Andrei Nigmatulin discovered a heap based buffer overflow flaw in the
ImageMagick image handler. An attacker could create a carefully crafted
Photoshop Document (PSD) image in such a way that it would cause
ImageMagick to execute arbitrary code when processing the image. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0005 to this issue.

A format string bug was found in the way ImageMagick handles filenames.
An attacker could execute arbitrary code in a victims machine if they
are able to trick the victim into opening a file with a specially
crafted name. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0397 to this issue.



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ImageMagick package";
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
if ( rpm_check( reference:"ImageMagick-6.2.0.7-2.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
}
