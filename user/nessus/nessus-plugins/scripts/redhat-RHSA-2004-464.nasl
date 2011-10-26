#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14740);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0494");

 name["english"] = "RHSA-2004-464: mc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mc package that resolves several shell escape security issues is
  now available.

  Midnight Commander (mc) is a visual shell much like a file manager.

  Shell escape bugs have been discovered in several of the mc vfs backend
  scripts. An attacker who is able to influence a victim to open a
  specially-crafted URI using mc could execute arbitrary commands as the
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has
  assigned the name CVE-2004-0494 to this issue.

  Users of mc should upgrade to this updated package which contains
  backported patches and is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-464.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mc packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mc-4.5.51-36.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0494", value:TRUE);
}

set_kb_item(name:"RHSA-2004-464", value:TRUE);
