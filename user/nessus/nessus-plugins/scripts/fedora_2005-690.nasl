#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19379);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 3 2005-690: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-690 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, and contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

To reduce the risk of future vulnerabilities in Ethereal,
the ethereal and tethereal programs in this update have been
compiled as Position Independant Executables (PIE).


Solution : http://www.fedoranews.org/blog/index.php?p=804
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.12-1.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.12-1.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-debuginfo-0.10.12-1.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
