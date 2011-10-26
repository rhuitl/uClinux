#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(22443);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-3016", "CVE-2006-4020", "CVE-2006-4482", "CVE-2006-4484", "CVE-2006-4486");

 name["english"] = "RHSA-2006-0669: php";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated PHP packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  A response-splitting issue was discovered in the PHP session handling. If
  a remote attacker can force a carefully crafted session identifier to be
  used, a cross-site-scripting or response-splitting attack could be
  possible. (CVE-2006-3016)

  A buffer overflow was discovered in the PHP sscanf() function. If a script
  used the sscanf() function with positional arguments in the format string,
  a remote attacker sending a carefully crafted request could execute
  arbitrary code as the \'apache\' user. (CVE-2006-4020)

  An integer overflow was discovered in the PHP wordwrap() and str_repeat()
  functions. If a script running on a 64-bit server used either of these
  functions on untrusted user data, a remote attacker sending a carefully
  crafted request might be able to cause a heap overflow. (CVE-2006-4482)

  A buffer overflow was discovered in the PHP gd extension. If a script was
  set up to process GIF images from untrusted sources using the gd extension,
  a remote attacker could cause a heap overflow. (CVE-2006-4484)

  An integer overflow was discovered in the PHP memory allocation handling.
  On 64-bit platforms, the "memory_limit" setting was not enforced correctly,
  which could allow a denial of service attack by a remote user.
  (CVE-2006-4486)

  Users of PHP should upgrade to these updated packages which contain
  backported patches to correct these issues. These packages also contain a
  fix for a bug where certain input strings to the metaphone() function could
  cause memory corruption.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0669.html
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
if ( rpm_check( reference:"php-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.2-36.ent", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-devel-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-domxml-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-gd-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-imap-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ldap-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mbstring-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-mysql-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-ncurses-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-odbc-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pear-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-pgsql-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-snmp-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"php-xmlrpc-4.3.9-3.18", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"php-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2006-3016", value:TRUE);
 set_kb_item(name:"CVE-2006-4020", value:TRUE);
 set_kb_item(name:"CVE-2006-4482", value:TRUE);
 set_kb_item(name:"CVE-2006-4484", value:TRUE);
 set_kb_item(name:"CVE-2006-4486", value:TRUE);
}
if ( rpm_exists(rpm:"php-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-3016", value:TRUE);
 set_kb_item(name:"CVE-2006-4020", value:TRUE);
 set_kb_item(name:"CVE-2006-4482", value:TRUE);
 set_kb_item(name:"CVE-2006-4484", value:TRUE);
 set_kb_item(name:"CVE-2006-4486", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0669", value:TRUE);
