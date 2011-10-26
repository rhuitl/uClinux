#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21721);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1173");

 name["english"] = "RHSA-2006-0515: sendmail";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated sendmail packages are now available to fix a denial of service
  security issue.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Sendmail is a Mail Transport Agent (MTA) used to send mail between machines.

  A flaw in the handling of multi-part MIME messages was discovered in
  Sendmail. A remote attacker could create a carefully crafted message that
  could crash the sendmail process during delivery (CVE-2006-1173). By
  default on Red Hat Enterprise Linux, Sendmail is configured to only accept
  connections from the local host. Therefore, only users who have configured
  Sendmail to listen to remote hosts would be remotely vulnerable to this issue.

  Users of Sendmail are advised to upgrade to these erratum packages, which
  contain a backported patch from the Sendmail team to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0515.html
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
if ( rpm_check( reference:"sendmail-8.12.11-4.21AS.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.11-4.21AS.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.11-4.21AS.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.11-4.21AS.10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.12.11-4.RHEL3.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.11-4.RHEL3.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.11-4.RHEL3.6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.11-4.RHEL3.5", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-8.13.1-3.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.13.1-3.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.13.1-3.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.13.1-3.RHEL4.5", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"sendmail-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-1173", value:TRUE);
}
if ( rpm_exists(rpm:"sendmail-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-1173", value:TRUE);
}
if ( rpm_exists(rpm:"sendmail-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1173", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0515", value:TRUE);
