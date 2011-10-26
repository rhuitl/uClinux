#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2004:033
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14769);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
 
 name["english"] = "SUSE-SA:2004:033: gtk2, gdk-pixbuf";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2004:033 (gtk2, gdk-pixbuf).


gdk-pixbuf is an image loading and rendering library mostly used
by GTK and GNOME applications. It is distributed as a separate
package for gtk1 and integrated into the gtk2 package. Chris
Evans has discovered a heap based, a stack based and an integer
overflow in the XPM and ICO loaders of those libraries. The
overflows can be exploited by tricking an application to display
a malformed image to make it crash or to execute code.


Solution : http://www.suse.de/security/2004_33_gtk2_gdk_pixbuf.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gtk2, gdk-pixbuf package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"gtk2-2.0.6-154", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.18.0-609", release:"SUSE8.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.2.1-102", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.18.0-609", release:"SUSE8.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.2.3-54", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.18.0-610", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gtk2-2.2.4-125.4", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gdk-pixbuf-0.22.0-62.7", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"gtk2-", release:"SUSE8.1")
 || rpm_exists(rpm:"gtk2-", release:"SUSE8.2")
 || rpm_exists(rpm:"gtk2-", release:"SUSE9.0")
 || rpm_exists(rpm:"gtk2-", release:"SUSE9.1") )
{
 set_kb_item(name:"CVE-2004-0782", value:TRUE);
 set_kb_item(name:"CVE-2004-0783", value:TRUE);
 set_kb_item(name:"CVE-2004-0788", value:TRUE);
}
