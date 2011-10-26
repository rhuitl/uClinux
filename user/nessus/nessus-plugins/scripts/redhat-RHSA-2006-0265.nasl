#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21135);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0058");

 name["english"] = "RHSA-2006-0265: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated sendmail packages to fix a security issue are now available for Red
  Hat Enterprise Linux 2.1.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Sendmail is a Mail Transport Agent (MTA) used to send mail between machines.

  A flaw in the handling of asynchronous signals was discovered in Sendmail.
  A remote attacker may be able to exploit a race condition to execute
  arbitrary code as root. The Common Vulnerabilities and Exposures project
  assigned the name CVE-2006-0058 to this issue.

  By default on Red Hat Enterprise Linux 2.1, Sendmail is configured to only
  accept connections from the local host. Therefore only users who have
  configured Sendmail to listen to remote hosts would be able to be remotely
  exploited by this vulnerability.

  In order to correct this issue for Red Hat Enterprise Linux 2.1 users, it
  was necessary to upgrade the version of Sendmail from 8.11 as originally
  shipped to Sendmail 8.12 with the addition of the security patch supplied
  by Sendmail Inc. This erratum provides updated packages based on Sendmail
  8.12 with a compatibility mode enabled. After updating to these packages,
  users should pay close attention to their sendmail logs to ensure that the
  upgrade completed sucessfully.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0265.html
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
if ( rpm_check( reference:"sendmail-8.12.11-4.21AS.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.11-4.21AS.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.11-4.21AS.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.11-4.21AS.8", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sendmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-0058", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0265", value:TRUE);
