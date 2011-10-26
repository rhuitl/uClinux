#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19660);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
 
 name["english"] = "Fedora Core 4 2005-751: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-751 (gaim).

Gaim is a clone of America Online's Instant Messenger client. It
features nearly all of the functionality of the official AIM client
while also being smaller, faster, and commercial-free.

Update Information:

[14]http://gaim.sourceforge.net/
Please see the Changelog details and security information at
the upstream Gaim Project site.


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-1.5.0-1.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gaim-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}
