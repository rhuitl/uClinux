#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21134);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0058");

 name["english"] = "RHSA-2006-0264: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated sendmail packages to fix a security issue are now available for Red
  Hat Enterprise Linux 3 and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Sendmail is a Mail Transport Agent (MTA) used to send mail between machines.

  A flaw in the handling of asynchronous signals was discovered in Sendmail.
  A remote attacker may be able to exploit a race condition to execute
  arbitrary code as root. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2006-0058 to this issue.

  By default on Red Hat Enterprise Linux 3 and 4, Sendmail is configured to
  only accept connections from the local host. Therefore, only users who have
  configured Sendmail to listen to remote hosts would be able to be remotely
  exploited by this vulnerability.

  Users of Sendmail are advised to upgrade to these erratum packages, which
  contain a backported patch from the Sendmail team to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0264.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the sendmail packages";
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
if ( rpm_check( reference:"sendmail-8.12.11-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.11-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.11-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.11-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.13.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.13.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.13.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.13.1-3.RHEL4.3", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sendmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-0058", value:TRUE);
}
if ( rpm_exists(rpm:"sendmail-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0058", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0264", value:TRUE);
