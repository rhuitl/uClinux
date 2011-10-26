#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21287);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-2933", "CVE-2005-3883", "CVE-2006-0208", "CVE-2006-0996", "CVE-2006-1490");

 name["english"] = "RHSA-2006-0276: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  The phpinfo() PHP function did not properly sanitize long strings. An
  attacker could use this to perform cross-site scripting attacks against
  sites that have publicly-available PHP scripts that call phpinfo().
  (CVE-2006-0996)

  The html_entity_decode() PHP function was found to not be binary safe. An
  attacker could use this flaw to disclose a certain part of the memory. In
  order for this issue to be exploitable the target site would need to have a
  PHP script which called the "html_entity_decode()" function with untrusted
  input from the user and displayed the result. (CVE-2006-1490)

  The error handling output was found to not properly escape HTML output in
  certain cases. An attacker could use this flaw to perform cross-site
  scripting attacks against sites where both display_errors and html_errors
  are enabled. (CVE-2006-0208)

  An input validation error was found in the "mb_send_mail()" function. An
  attacker could use this flaw to inject arbitrary headers in a mail sent via
  a script calling the "mb_send_mail()" function where the "To" parameter can
  be controlled by the attacker. (CVE-2005-3883)

  A buffer overflow flaw was discovered in uw-imap, the University of
  Washington\'s IMAP Server. php-imap is compiled against the static c-client
  libraries from imap and therefore needed to be recompiled against the fixed
  version. This issue only affected Red Hat Enterprise Linux 3.
  (CVE-2005-2933).

  Users of PHP should upgrade to these updated packages, which contain
  backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0276.html
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
if ( rpm_check( reference:"php-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-30.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.12", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
 set_kb_item(name:"CVE-2005-3883", value:TRUE);
 set_kb_item(name:"CVE-2006-0208", value:TRUE);
 set_kb_item(name:"CVE-2006-0996", value:TRUE);
 set_kb_item(name:"CVE-2006-1490", value:TRUE);
}
if ( rpm_exists(rpm:"php-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2933", value:TRUE);
 set_kb_item(name:"CVE-2005-3883", value:TRUE);
 set_kb_item(name:"CVE-2006-0208", value:TRUE);
 set_kb_item(name:"CVE-2006-0996", value:TRUE);
 set_kb_item(name:"CVE-2006-1490", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0276", value:TRUE);
