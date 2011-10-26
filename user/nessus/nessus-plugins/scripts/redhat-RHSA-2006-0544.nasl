#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21683);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-2753");

 name["english"] = "RHSA-2006-0544: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mysql packages that fix multiple security flaws are now available.

  This update has been rated as having important security impact by the Red Hat
  Security Response Team.

  MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
  client/server implementation consisting of a server daemon (mysqld) and
  many different client programs and libraries.

  A flaw was found in the way the MySQL mysql_real_escape() function escaped
  strings when operating in a multibyte character encoding. An attacker
  could provide an application a carefully crafted string containing
  invalidly-encoded characters which may be improperly escaped, leading to
  the injection of malicious SQL commands. (CVE-2006-2753)

  An information disclosure flaw was found in the way the MySQL server
  processed malformed usernames. An attacker could view a small portion
  of server memory by supplying an anonymous login username which was not
  null terminated. (CVE-2006-1516)

  An information disclosure flaw was found in the way the MySQL server
  executed the COM_TABLE_DUMP command. An authenticated malicious user could
  send a specially crafted packet to the MySQL server which returned
  random unallocated memory. (CVE-2006-1517)

  A log file obfuscation flaw was found in the way the mysql_real_query()
  function creates log file entries. An attacker with the the ability to call
  the mysql_real_query() function against a mysql server can obfuscate the
  entry the server will write to the log file. However, an attacker needed
  to have complete control over a server in order to attempt this attack.
  (CVE-2006-0903)

  This update also fixes numerous non-security-related flaws, such as
  intermittent authentication failures.

  All users of mysql are advised to upgrade to these updated packages
  containing MySQL version 4.1.20, which is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2006-0544.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql packages";
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
if ( rpm_check( reference:"mysql-4.1.20-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-bench-4.1.20-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-4.1.20-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-4.1.20-1.RHEL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mysql-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2006-0903", value:TRUE);
 set_kb_item(name:"CVE-2006-1516", value:TRUE);
 set_kb_item(name:"CVE-2006-1517", value:TRUE);
 set_kb_item(name:"CVE-2006-2753", value:TRUE);
}

set_kb_item(name:"RHSA-2006-0544", value:TRUE);
