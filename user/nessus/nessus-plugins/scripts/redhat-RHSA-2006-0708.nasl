#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22524);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-4812");

 name["english"] = "RHSA-2006-0708: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix an integer overflow flaw are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  An integer overflow was discovered in the PHP memory handling routines. If
  a script can cause memory allocation based on untrusted user data, a remote
  attacker sending a carefully crafted request could execute arbitrary code
  as the \'apache\' user. (CVE-2006-4812)

  This issue did not affect the PHP packages distributed with Red Hat
  Enterprise Linux 3 or 4.

  Users of PHP should upgrade to these updated packages which contain a
  backported patch that corrects this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0708.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php packages";
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
if ( rpm_check( reference:"php-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.12", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2006-4812", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0708", value:TRUE);
