#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:065
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20239);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2005:065: gtk2, gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:065 (gtk2, gdk-pixbuf).


The image loading library of the gdk-pixbug/gtk2 package is vulnerable
to several security-related bugs. This makes every application (mostly
GNOME applications) which is linked against this library vulnerable too.

A carefully crafted XPM file can be used to execute arbitrary code while
processing the image file. (CVE-2005-3186)

Additionally Ludwig Nussel from the SuSE Security-Team discovered an
integer overflow bug that can be used to execute arbitray code too
(CVE-2005-2976), and an infinite loop which leads to a denial-of-service
bug. (CVE-2005-2975)


Solution : http://www.suse.de/security/advisories/2005_65_gtk2.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtk2, gdk-pixbuf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gtk2-2.8.3-4.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.8.3-4.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-72.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-72.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.2.3-57", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.2.3-57", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.18.0-615", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.18.0-615", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.2.4-125.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.2.4-125.10", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-62.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-62.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.4.9-10.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.4.9-10.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-64.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-64.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.6.4-6.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-devel-2.6.4-6.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-67.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-devel-0.22.0-67.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
