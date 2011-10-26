#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14373);
 script_bugtraq_id(11056);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0785");
 
 name["english"] = "Fedora Core 1 2004-278: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-278 (gaim).

Gaim allows you to talk to anyone using a variety of messaging
protocols, including AIM (Oscar and TOC), ICQ, IRC, Yahoo!,
MSN Messenger, Jabber, Gadu-Gadu, Napster, and Zephyr.  These
protocols are implemented using a modular, easy to use design.
To use a protocol, just add an account using the account editor.

Gaim supports many common features of other clients, as well as many
unique features, such as perl scripting and C plugins.

Gaim is NOT affiliated with or endorsed by America Online, Inc.,
Microsoft Corporation, or Yahoo! Inc. or other messaging service
providers.

Update Information:

0.82 update contains many bug and security improvements.



Solution : http://www.fedoranews.org/updates/FEDORA-2004-278.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim package";
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
if ( rpm_check( reference:"gaim-0.82-0.FC1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-debuginfo-0.82-0.FC1", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gaim-", release:"FC1") )
{
 set_kb_item(name:"CVE-2004-0785", value:TRUE);
}
