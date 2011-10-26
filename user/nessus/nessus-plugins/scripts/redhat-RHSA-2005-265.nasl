#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17268);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0455", "CVE-2005-0611");

 name["english"] = "RHSA-2005-265: RealPlayer";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated RealPlayer package that fixes two buffer overflow issues is now
  available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  RealPlayer is a media player.

  A stack based buffer overflow bug was found in RealPlayer\'s Synchronized
  Multimedia Integration Language (SMIL) file processor. An attacker could
  create a specially crafted SMIL file which would execute arbitrary code
  when opened by a user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0455 to this issue.

  A buffer overflow bug was found in the way RealPlayer decodes WAV sound
  files. An attacker could create a specially crafted WAV file which could
  execute arbitrary code when opened by a user. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2005-0611
  to this issue.

  All users of RealPlayer are advised to upgrade to this updated package,
  which contains RealPlayer version 10.0.3 and is not vulnerable to these
  issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-265.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the RealPlayer packages";
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
if ( rpm_check( reference:"RealPlayer-10.0.3-1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"RealPlayer-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0455", value:TRUE);
 set_kb_item(name:"CVE-2005-0611", value:TRUE);
}

set_kb_item(name:"RHSA-2005-265", value:TRUE);
