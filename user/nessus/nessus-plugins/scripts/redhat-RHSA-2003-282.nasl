#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15652);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2003-0780");

 name["english"] = "RHSA-2003-282: mysql";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated MySQL server packages fix a buffer overflow vulnerability.

  MySQL is a multi-user, multi-threaded SQL database server.

  Frank Denis reported a bug in unpatched versions of MySQL prior to version
  3.23.58. Passwords for MySQL users are stored in the Password field of the
  user table. Under this bug, a Password field with a value greater than 16
  characters can cause a buffer overflow. It may be possible for an attacker
  with the ability to modify the user table to exploit this buffer overflow
  to execute arbitrary code as the MySQL user. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2003-0780 to
  this issue.

  Users of MySQL are advised to upgrade to these erratum packages containing
  MySQL 3.23.58, which is not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2003-282.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mysql packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"mysql-3.23.58-1.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-devel-3.23.58-1.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mysql-server-3.23.58-1.72", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"mysql-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0780", value:TRUE);
}

set_kb_item(name:"RHSA-2003-282", value:TRUE);
