#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14703);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0817");
 
 name["english"] = "Fedora Core 1 2004-300: imlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-300 (imlib).

Imlib is a display depth independent image loading and rendering
library. Imlib is designed to simplify and speed up the process of
loading images and obtaining X Window System drawables. Imlib
provides many simple manipulation routines which can be used for
common operations.

Install imlib if you need an image loading and rendering library for
X11R6, or if you are installing GNOME. You may also want to install
the imlib-cfgeditor package, which will help you configure Imlib.

Update Information:

Several heap overflow vulnerabilities have been found in the imlib BMP
image handler. An attacker could create a carefully crafted BMP file in
such a way that it would cause an application linked with imlib to
execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name
CVE-2004-0817 to this issue.

Users of imlib should update to this updated package which contains
backported patches and is not vulnerable to these issues.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-300.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib package";
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
if ( rpm_check( reference:"imlib-1.9.13-15.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-15.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-15.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-debuginfo-1.9.13-15.fc1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"imlib-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0817", value:TRUE);
}
