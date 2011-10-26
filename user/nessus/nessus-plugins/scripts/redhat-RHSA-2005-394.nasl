#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18111);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0755");

 name["english"] = "RHSA-2005-394: realplayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated RealPlayer package that fixes a buffer overflow issue is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  RealPlayer is a media player providing solid media playback locally
  and via streaming. It plays RealAudio, RealVideo, MP3, 3GPP Video,
  Flash, SMIL 2.0, JPEG, GIF, PNG, RealPix and RealText and
  more.

  A buffer overflow bug was found in the way RealPlayer processes RAM files.
  An attacker could create a specially crafted RAM file which could execute
  arbitrary code when opened by a user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0755 to
  this issue.

  All users of RealPlayer are advised to upgrade to this updated package,
  which contains RealPlayer version 10.0.4 and is not vulnerable to this
  issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-394.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the realplayer packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"realplayer-10.0.4-1", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"realplayer-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0755", value:TRUE);
}

set_kb_item(name:"RHSA-2005-394", value:TRUE);
