#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19491);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2498");

 name["english"] = "RHSA-2005-748: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A bug was discovered in the PEAR XML-RPC Server package included in PHP. If
  a PHP script is used which implements an XML-RPC Server using the PEAR
  XML-RPC package, then it is possible for a remote attacker to construct an
  XML-RPC request which can cause PHP to execute arbitrary PHP commands as
  the \'apache\' user. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-2498 to this issue.

  When using the default SELinux "targeted" policy on Red Hat Enterprise
  Linux 4, the impact of this issue is reduced since the scripts executed by
  PHP are constrained within the httpd_sys_script_t security context.

  Users of PHP should upgrade to these updated packages, which contain
  backported fixes for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-748.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the php packages";
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
if ( rpm_check( reference:"php-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-25.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2498", value:TRUE);
}
if ( rpm_exists(rpm:"php-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2498", value:TRUE);
}

set_kb_item(name:"RHSA-2005-748", value:TRUE);
