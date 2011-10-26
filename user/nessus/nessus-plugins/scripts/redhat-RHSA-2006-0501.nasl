#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21594);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2933", "CVE-2006-0208", "CVE-2006-0996", "CVE-2006-1990");

 name["english"] = "RHSA-2006-0501: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  The phpinfo() PHP function did not properly sanitize long strings. An
  attacker could use this to perform cross-site scripting attacks against
  sites that have publicly-available PHP scripts that call phpinfo().
  (CVE-2006-0996)

  The error handling output was found to not properly escape HTML output in
  certain cases. An attacker could use this flaw to perform cross-site
  scripting attacks against sites where both display_errors and html_errors
  are enabled. (CVE-2006-0208)

  A buffer overflow flaw was discovered in uw-imap, the University of
  Washington\'s IMAP Server. php-imap is compiled against the static c-client
  libraries from imap and therefore needed to be recompiled against the fixed
  version. (CVE-2005-2933)

  The wordwrap() PHP function did not properly check for integer overflow in
  the handling of the "break" parameter. An attacker who could control the
  string passed to the "break" parameter could cause a heap overflow.
  (CVE-2006-1990)

  Users of PHP should upgrade to these updated packages, which contain
  backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0501.html
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
if ( rpm_check( reference:"php-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-manual-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.1.2-2.6", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
 set_kb_item(name:"CVE-2006-0208", value:TRUE);
 set_kb_item(name:"CVE-2006-0996", value:TRUE);
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0501", value:TRUE);
