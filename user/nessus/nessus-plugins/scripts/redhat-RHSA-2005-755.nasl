#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19544);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2665");

 name["english"] = "RHSA-2005-755: elm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated elm package is now available that fixes a buffer overflow issue
  for Red Hat Enterprise Linux 2.1 AS and AW.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Elm is a terminal mode email client.

  A buffer overflow flaw in Elm was discovered that was triggered by viewing
  a mailbox containing a message with a carefully crafted \'Expires\' header.
  An attacker could create a malicious message that would execute arbitrary
  code with the privileges of the user who received it. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-2665 to this issue.

  Users of Elm should update to this updated package, which contains a
  backported patch that corrects this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-755.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the elm packages";
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
if ( rpm_check( reference:"elm-2.5.6-6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"elm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2665", value:TRUE);
}

set_kb_item(name:"RHSA-2005-755", value:TRUE);
