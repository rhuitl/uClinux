#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18581);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-483: HelixPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-483 (HelixPlayer).

The Helix Player 1.0 is an open-source media player built in the Helix
Community for consumers. Built using GTK, it plays open source formats,
like Ogg Vorbis and Theora using the powerful Helix DNA Client Media
Engine.


* Fri Jun 24 2005 Colin Walters <walters@redhat.com> 1:1.0.5-1.fc4.2

- Update work done by John (J5) Palmieri <johnp@redhat.com>
- Update to 1.0.5 as fix for bug #159872
- add missing header patch



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_HelixPlayer-1.0.5-1.fc4.2
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
if ( rpm_check( reference:"HelixPlayer-1.0.5-1.fc4.2", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
