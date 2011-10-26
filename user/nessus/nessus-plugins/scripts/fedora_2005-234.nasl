#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18316);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0827", "CVE-2004-0981", "CVE-2005-0005", "CVE-2005-0397");
 
 name["english"] = "Fedora Core 2 2005-234: ImageMagick";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-234 (ImageMagick).

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
ImageMagick image handler. An attacker could create a carefully
crafted
Photoshop Document (PSD) image in such a way that it would cause
ImageMagick to execute arbitrary code when processing the image. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0005 to this issue.

A format string bug was found in the way ImageMagick handles
filenames.
An attacker could execute arbitrary code in a victims machine if they
are able to trick the victim into opening a file with a specially
crafted name. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0397 to this issue.

A bug was found in the way ImageMagick handles TIFF tags. It is
possible
that a TIFF image file with an invalid tag could cause ImageMagick to
crash.

A bug was found in ImageMagick's TIFF decoder. It is possible that a
specially crafted TIFF image file could cause ImageMagick to crash.

A bug was found in the way ImageMagick parses PSD files. It is
possilbe
that a specially crafted PSD file could cause ImageMagick to crash.

A heap overflow bug was found in ImageMagick's SGI parser. It is
possible
that an attacker could execute arbitrary code by tricking a user into
opening a specially crafted SGI image file.


Solution : http://www.fedoranews.org/blog/index.php?p=550
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
if ( rpm_check( reference:"ImageMagick-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-debuginfo-6.2.0.7-2.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"ImageMagick-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0827", value:TRUE);
 set_kb_item(name:"CVE-2004-0981", value:TRUE);
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
}
