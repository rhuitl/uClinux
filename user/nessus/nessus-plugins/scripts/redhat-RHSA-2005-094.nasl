#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17184);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0149");

 name["english"] = "RHSA-2005-094: thunderbird";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Thunderbird package that fixes a security issue is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Thunderbird is a standalone mail and newsgroup client.

  A bug was found in the way Thunderbird handled cookies when loading content
  over HTTP regardless of the user\'s preference. It is possible that a
  particular user could be tracked through the use of malicious mail messages
  which load content over HTTP. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CVE-2005-0149 to this issue.

  Users of Thunderbird are advised to upgrade to this updated package,
  which contains Thunderbird version 1.0 and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-094.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the thunderbird packages";
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
if ( rpm_check( reference:"thunderbird-1.0-1.1.EL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"thunderbird-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0149", value:TRUE);
}

set_kb_item(name:"RHSA-2005-094", value:TRUE);
