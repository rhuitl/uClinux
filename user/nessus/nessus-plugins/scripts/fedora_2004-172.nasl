#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13726);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 2 2004-172: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-172 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

These new packages fix a bug in the last errata where the actual
security patch didn't get applied.

All users of ethereal are strongly recommended to update to these latest
packages.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-172.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ethereal package";
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
if ( rpm_check( reference:"ethereal-0.10.3-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-debuginfo-0.10.3-2.2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
