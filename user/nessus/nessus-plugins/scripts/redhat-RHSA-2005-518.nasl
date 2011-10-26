#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18511);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1269", "CVE-2005-1934");

 name["english"] = "RHSA-2005-518: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes two denial of service issues is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  Jacopo Ottaviani discovered a bug in the way Gaim handles Yahoo! Messenger
  file transfers. It is possible for a malicious user to send a specially
  crafted file transfer request that causes Gaim to crash. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2005-1269 to this issue.

  Additionally, Hugo de Bokkenrijder discovered a bug in the way Gaim parses
  MSN Messenger messages. It is possible for a malicious user to send a
  specially crafted MSN Messenger message that causes Gaim to crash. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-1934 to this issue.

  Users of gaim are advised to upgrade to this updated package, which
  contains
  version 1.3.1 and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-518.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gaim packages";
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
if ( rpm_check( reference:"gaim-1.3.1-0.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.3.1-0.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1269", value:TRUE);
 set_kb_item(name:"CVE-2005-1934", value:TRUE);
}
if ( rpm_exists(rpm:"gaim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1269", value:TRUE);
 set_kb_item(name:"CVE-2005-1934", value:TRUE);
}

set_kb_item(name:"RHSA-2005-518", value:TRUE);
