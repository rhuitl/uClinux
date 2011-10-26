# This script was automatically generated from the SSA-2006-155-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New mysql packages are available for Slackware 9.1, 10.0, 10.1,
10.2 and -current to fix security issues.


The MySQL packages shipped with Slackware 9.1, 10.0, and 10.1
may possibly leak sensitive information found in uninitialized
memory to authenticated users.  This is fixed in the new packages,
and was already patched in Slackware 10.2 and -current.
Since the vulnerabilities require a valid login and/or access to the
database server, the risk is moderate.  Slackware does not provide
network access to a MySQL database by default.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database.
Fixes that affect Slackware 9.1, 10.0, and 10.1:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1516
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1517


The MySQL packages in Slackware 10.2 and -current have been
upgraded to MySQL 4.1.20 (Slackware 10.2) and MySQL 5.0.22
(Slackware -current) to fix an SQL injection vulnerability.

For more details, see the MySQL 4.1.20 release announcement here:
  http://lists.mysql.com/announce/364
And the MySQL 5.0.22 release announcement here:
  http://lists.mysql.com/announce/365
The CVE entry for this issue can be found here:
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2753


Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
patches/packages/mysql-4.0.27-i486-1_slack10.1.tgz:
  Upgraded to mysql-4.0.27.
  This fixes some minor security issues with possible information leakage.
  Note that the information leakage bugs require that the attacker have
  access to an account on the database.  Also note that by default,
  Slackware\'s rc.mysqld script does *not* allow access to the database
  through the outside network (it uses the --skip-networking option).
  If you\'ve enabled network access to MySQL, it is a good idea to filter
  the port (3306) to prevent access from unauthorized machines.
  For more details, see the MySQL 4.0.27 release announcement here:
    http://lists.mysql.com/announce/359
  For more information, see:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1516
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1517
  (* Security fix *)
+--------------------------+

';
if (description) {
script_id(21639);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-155-01");
script_summary("SSA-2006-155-01 mysql ");
name["english"] = "SSA-2006-155-01 mysql ";
script_name(english:name["english"]);
script_cve_id("CVE-2006-1516","CVE-2006-1517","CVE-2006-2753");
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "mysql", pkgver: "5.0.22", pkgnum:  "1", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package mysql is vulnerable in Slackware -current
Upgrade to mysql-5.0.22-i486-1 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
