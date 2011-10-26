#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15732);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0941", "CVE-2004-0990");
 
 name["english"] = "Fedora Core 2 2004-411: gd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-411 (gd).

The gd graphics library allows your code to quickly draw images
complete with lines, arcs, text, multiple colors, cut and paste from
other images, and flood fills, and to write out the result as a PNG or
JPEG file. This is particularly useful in Web applications, where PNG
and JPEG are two of the formats accepted for inline images by most
browsers. Note that gd is not a paint program.

Update Information:

Several buffer overflows were reported in various memory allocation
calls.
An attacker could create a carefully crafted image file in such a
way that it could cause ImageMagick to execute arbitrary code when
processing the image. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0990 to these issues.

Whilst researching the fixes to these overflows, additional buffer
overflows were discovered in calls to gdMalloc. The Common
Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0941
to these issues.

Users of gd should upgrade to these updated packages, which contain a
backported security patch, and are not vulnerable to these issues.


Solution : http://www.fedoranews.org/blog/index.php?p=68
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gd package";
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
if ( rpm_check( reference:"gd-2.0.21-5.20.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-progs-2.0.21-5.20.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-devel-2.0.21-5.20.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gd-debuginfo-2.0.21-5.20.1", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gd-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}
