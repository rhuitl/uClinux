#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19322);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Fedora Core 4 2005-680: NetworkManager";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-680 (NetworkManager).

NetworkManager attempts to keep an active network connection available at all
times.  It is intended only for the desktop use-case, and is not intended for
usage on servers.   The point of NetworkManager is to make networking
configuration and setup as painless and automatic as possible.  If using DHCP,
NetworkManager is _intended_ to replace default routes, obtain IP addresses
from a DHCP server, and change nameservers whenever it sees fit.

Update Information:

Network Manager passes logging messages straight to syslog
as the format string.
This causes it to crash when connecting to access points
that contain format string characters.

This was reported initially by Ian Jackson:

http://mail.gnome.org/archives/networkmanager-list/2005-July/msg00196.html



Solution : http://fedoranews.org//mediawiki/index.php/Fedora_Core_4_Update:_NetworkManager-0.4-20.FC4.1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the NetworkManager package";
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
if ( rpm_check( reference:"NetworkManager-0.4-20.FC4.1", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
