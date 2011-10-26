#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22044);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1494", "CVE-2006-1990", "CVE-2006-3017");

 name["english"] = "RHSA-2006-0568: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A directory traversal vulnerability was found in PHP. Local users could
  bypass open_basedir restrictions allowing remote attackers to create files
  in arbitrary directories via the tempnam() function. (CVE-2006-1494)

  The wordwrap() PHP function did not properly check for integer overflow in
  the handling of the "break" parameter. An attacker who could control the
  string passed to the "break" parameter could cause a heap overflow.
  (CVE-2006-1990)

  A flaw was found in the zend_hash_del() PHP function. For PHP scripts that
  rely on the use of the unset() function, a remote attacker could force
  variable initialization to be bypassed. This would be a security issue
  particularly for installations that enable the "register_globals" setting.
  "register_globals" is disabled by default in Red Hat Enterprise Linux.
  (CVE-2006-3017)

  Users of PHP should upgrade to these updated packages, which contain
  backported patches that resolve these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0568.html
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
if ( rpm_check( reference:"php-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-33.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.15", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-1494", value:TRUE);
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
 set_kb_item(name:"CVE-2006-3017", value:TRUE);
}
if ( rpm_exists(rpm:"php-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-1494", value:TRUE);
 set_kb_item(name:"CVE-2006-1990", value:TRUE);
 set_kb_item(name:"CVE-2006-3017", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0568", value:TRUE);
