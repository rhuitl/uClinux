#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19623);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0455", "CVE-2005-0611");
 
 name["english"] = "Fedora Core 3 2005-188: HelixPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-188 (HelixPlayer).

The Helix Player 1.0 is an open-source media player built in the Helix
Community for consumers. Built using GTK, it plays open source formats,
like Ogg Vorbis and Theora using the powerful Helix DNA Client Media
Engine.

Update Information:

Updated HelixPlayer packages that fixes two buffer overflow issues are
now
available.

This update has been rated as having critical security impact by the Red
Hat Security Response Team.

A stack based buffer overflow bug was found in HelixPlayer's
Synchronized Multimedia Integration Language (SMIL) file processor. An
attacker could create a specially crafted SMIL file which would execute
arbitrary code when opened by a user. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0455 to
this issue.

A buffer overflow bug was found in the way HelixPlayer decodes WAV
files. An attacker could create a specially crafted WAV file which could
execute arbitrary code when opened by a user. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0611 to this issue.

All users of HelixPlayer are advised to upgrade to this updated package,
which contains HelixPlayer 1.0.3 which is not vulnerable to these
issues.


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
if ( rpm_check( reference:"HelixPlayer-1.0.3-3.fc3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"HelixPlayer-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0455", value:TRUE);
 set_kb_item(name:"CVE-2005-0611", value:TRUE);
}
