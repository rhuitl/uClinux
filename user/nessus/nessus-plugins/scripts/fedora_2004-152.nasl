#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13712);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Fedora Core 1 2004-152: ethereal";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-152 (ethereal).

Ethereal is a network traffic analyzer for Unix-ish operating systems.

This package lays base for libpcap, a packet capture and filtering
library, contains command-line utilities, contains plugins and
documentation for ethereal. A graphical user interface is packaged
separately to GTK+ package.

Update Information:

 Issues have been discovered in the following protocol dissectors:

    * A SIP packet could make Ethereal crash under specific conditions,
as described in the following message:
      http://www.ethereal.com/lists/ethereal-users/200405/msg00018.html
      (0.10.3).
    * The AIM dissector could throw an assertion, causing Ethereal to
terminate abnormally (0.10.3).
    * It was possible for the SPNEGO dissector to dereference a null
pointer, causing a crash (0.9.8 to 0.10.3).
    * The MMSE dissector was susceptible to a buffer overflow. (0.10.1
to 0.10.3).

All users of Ethereal are strongly encouraged to update to these latest
packages.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-152.shtml
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
if ( rpm_check( reference:"ethereal-0.10.3-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-gnome-0.10.3-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ethereal-debuginfo-0.10.3-0.1.1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
