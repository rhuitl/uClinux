#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19624);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 2 2005-202: grip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-202 (grip).

Grip is a GTK+ based front-end for CD rippers (such as cdparanoia and
cdda2wav) and Ogg Vorbis encoders.  Grip allows you to rip entire tracks or
just a section of a track.  Grip supports the CDDB protocol for
accessing track information on disc database servers.

Update Information:

This fixes a buffer overflow when the CDDB server returns more than 16
matches.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the grip package";
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
if ( rpm_check( reference:"grip-3.2.0-3.fc2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
