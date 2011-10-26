#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19881);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2710");
 
 name["english"] = "Fedora Core 3 2005-941: HelixPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-941 (HelixPlayer).

The Helix Player 1.0 is an open-source media player built in the Helix
Community for consumers. Built using GTK, it plays open source formats,
like Ogg Vorbis and Theora using the powerful Helix DNA Client Media
Engine.

Update Information:

This is a fix for CVE-2005-2710


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the HelixPlayer package";
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
if ( rpm_check( reference:"HelixPlayer-1.0.6-0.fc3.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"HelixPlayer-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-2710", value:TRUE);
}
