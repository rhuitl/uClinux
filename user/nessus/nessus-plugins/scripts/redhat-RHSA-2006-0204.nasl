#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21034);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-3573", "CVE-2005-4153");

 name["english"] = "RHSA-2006-0204: mailman";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated mailman package that fixes two security issues is now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mailman is software to help manage email discussion lists.

  A flaw in handling of UTF8 character encodings was found in Mailman. An
  attacker could send a carefully crafted email message to a mailing list run
  by Mailman which would cause that particular mailing list to stop working.
  The Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-3573 to this issue.

  A flaw in date handling was found in Mailman version 2.1.4 through 2.1.6.
  An attacker could send a carefully crafted email message to a mailing list
  run by Mailman which would cause the Mailman server to crash.
  (CVE-2005-4153).

  Users of Mailman should upgrade to this updated package, which contains
  backported patches to correct these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0204.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mailman packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mailman-2.1.5.1-25.rhel3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mailman-2.1.5.1-34.rhel4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mailman-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-3573", value:TRUE);
 set_kb_item(name:"CVE-2005-4153", value:TRUE);
}
if ( rpm_exists(rpm:"mailman-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-3573", value:TRUE);
 set_kb_item(name:"CVE-2005-4153", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0204", value:TRUE);
