#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18240);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1261", "CVE-2005-1262");

 name["english"] = "RHSA-2005-429: gaim";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated gaim package that fixes two security issues is now available.

  This update has been rated as having critical security impact by the Red
  Hat
  Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  A stack based buffer overflow bug was found in the way gaim processes a
  message containing a URL. A remote attacker could send a carefully crafted
  message resulting in the execution of arbitrary code on a victim\'s machine.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1261 to this issue.

  A bug was found in the way gaim handles malformed MSN messages. A remote
  attacker could send a carefully crafted MSN message causing gaim to crash.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2005-1262 to this issue.

  Users of Gaim are advised to upgrade to this updated package which contains
  backported patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-429.html
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
if ( rpm_check( reference:"gaim-1.2.1-6.el3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gaim-1.2.1-6.el4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gaim-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-1261", value:TRUE);
 set_kb_item(name:"CVE-2005-1262", value:TRUE);
}
if ( rpm_exists(rpm:"gaim-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-1261", value:TRUE);
 set_kb_item(name:"CVE-2005-1262", value:TRUE);
}

set_kb_item(name:"RHSA-2005-429", value:TRUE);
