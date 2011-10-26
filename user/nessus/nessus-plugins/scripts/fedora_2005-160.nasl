#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19619);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0472", "CVE-2005-0473");
 
 name["english"] = "Fedora Core 3 2005-160: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-160 (gaim).

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

* Sat Feb 19 2005 Warren Togami <wtogami redhat com> 1:1.1.3-1.FC3
- FC3

* Fri Feb 18 2005 Warren Togami <wtogami redhat com> 1:1.1.3-2
- 1.1.3 including two security fixes
CVE-2005-0472 Client freezes when receiving certain invalid messages
CVE-2005-0473 Client crashes when receiving specific malformed HTML



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
if ( rpm_check( reference:"gaim-1.1.3-1.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-debuginfo-1.1.3-1.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"gaim-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0472", value:TRUE);
 set_kb_item(name:"CVE-2005-0473", value:TRUE);
}
