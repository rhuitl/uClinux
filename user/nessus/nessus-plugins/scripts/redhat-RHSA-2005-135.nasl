#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16370);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");

 name["english"] = "RHSA-2005-135:   squirrelmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated Squirrelmail package that fixes several security issues is now
  available for Red Hat Enterprise Linux 3.

  SquirrelMail is a standards-based webmail package written in PHP4.

  Jimmy Conner discovered a missing variable initialization in Squirrelmail.
  This flaw could allow potential insecure file inclusions on servers where
  the PHP setting "register_globals" is set to "On". This is not a default or
  recommended setting. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0075 to this issue.

  A URL sanitisation bug was found in Squirrelmail. This flaw could allow a
  cross site scripting attack when loading the URL for the sidebar. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2005-0103 to this issue.

  A missing variable initialization bug was found in Squirrelmail. This flaw
  could allow a cross site scripting attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2005-0104 to
  this issue.

  Users of Squirrelmail are advised to upgrade to this updated package,
  which contains backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-135.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the   squirrelmail packages";
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
if ( rpm_check( reference:"squirrelmail-1.4.3a-9.EL3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"squirrelmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-0075", value:TRUE);
 set_kb_item(name:"CVE-2005-0103", value:TRUE);
 set_kb_item(name:"CVE-2005-0104", value:TRUE);
}

set_kb_item(name:"RHSA-2005-135", value:TRUE);
