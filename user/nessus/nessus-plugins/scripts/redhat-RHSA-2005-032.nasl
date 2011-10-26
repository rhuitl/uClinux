#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17166);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1018", "CVE-2004-1019", "CVE-2004-1065");

 name["english"] = "RHSA-2005-032: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated php packages that fix various security issues are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  Flaws including possible information disclosure, double free, and negative
  reference index array underflow were found in the deserialization code of
  PHP. PHP applications may use the unserialize function on untrusted user
  data, which could allow a remote attacker to gain access to memory or
  potentially execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-1019 to
  this issue.

  A flaw in the exif extension of PHP was found which lead to a stack
  overflow. An attacker could create a carefully crafted image file in such
  a way which, if parsed by a PHP script using the exif extension, could
  cause a crash or potentially execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-1065 to this issue.

  Flaws were found in shmop_write, pack, and unpack PHP functions. These
  functions are not normally passed user supplied data, so would require a
  malicious PHP script to be exploited. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2004-1018 to
  this issue.

  Users of PHP should upgrade to these updated packages, which contain fixes
  for these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2005-032.html
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
if ( rpm_check( reference:"php-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2004-1018", value:TRUE);
 set_kb_item(name:"CVE-2004-1019", value:TRUE);
 set_kb_item(name:"CVE-2004-1065", value:TRUE);
}

set_kb_item(name:"RHSA-2005-032", value:TRUE);
