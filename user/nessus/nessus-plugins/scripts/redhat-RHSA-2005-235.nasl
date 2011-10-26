#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17589);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1177");

 name["english"] = "RHSA-2005-235: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mailman package that corrects a cross-site scripting flaw is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mailman manages electronic mail discussion and e-newsletter lists.

  A cross-site scripting (XSS) flaw in the driver script of mailman prior to
  version 2.1.5 could allow remote attackers to execute scripts as other web
  users. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2004-1177 to this issue.

  Users of mailman should update to this erratum package, which corrects this
  issue by turning on STEALTH_MODE by default and using Utils.websafe() to
  quote the html.




Solution : http://rhn.redhat.com/errata/RHSA-2005-235.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
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
if ( rpm_check( reference:"mailman-2.1.5-25.rhel3", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5-33.rhel4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
}
if ( rpm_exists(rpm:"mailman-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1177", value:TRUE);
}

set_kb_item(name:"RHSA-2005-235", value:TRUE);
